# -*- coding: utf-8 -*-
"""
橘汁视频 gdsaj.hzhcbkj.cn | TVBox / AVBox Python 爬虫 

合并来源:
  A. 新协议栈版本: 新域名/包名/证书、_pb 标准 varint tag、双加密通道、plat=tv
  B. 上一版可用性兜底: 通道探测、观看记录兜底、converUrl 原生筛选、简介前缀
  C. AVBox 兼容: 无 pycryptodome 时纯 Python AES/RSA 回退, init 不联网

关键修复:
  1) _pb 字段号按 varint 读 (fn=29 的 tag 是 0xEA 0x01 双字节),
     旧版 fn=b>>3 只读一字节 -> 整体错位, 才被迫用 find(b'\xea\x01') 硬扫
  2) proto/v5 请求体: 双层 AES(SAFE->SAFECODE) + 'query=' 前缀, 再外层 AES(SAFECODE)
     ex/v3 响应体: 先 SAFECODE 解一层, 再 SAFE 解一层
  3) init 只做本地初始化; 登录/取二级公钥改懒加载, 失败 60s 后可重试
  4) 简介统一加 INTRO_PREFIX; 集名 "第01集"->"01"; 线路按 _line_rank 排序

V7.1 增量(短剧/筛选/地址编码):
  5) 短剧 fn=29 结构: 一条记录 = 一条线路的一个播放位置。单条线路(短剧"全集"、
     单片) 统一显示为「正片」, 避免 TVBox 显示成 "1"; 备注优先用站点原文(全47集)
  6) 列表条目补全 vod_year(fn14)/vod_area(fn1)/vod_director(fn7)/vod_actor(fn12),
     筛选结果不再缺年份地区
  7) 线路排序: 直链蓝光/4K 在前, BL/QQ/YK/QY 等纯站代号(网页解析源)垫底
  8) 中文路径百分号编码 _q_url(): p.b8bf.com/.../全集/index.m3u8 直接请求会 404
  9) 解析源回传图床封面(~image.image / tplv-xxx-image)判定失败, 不再当播放地址
"""
import re
import sys
import json
import time
import base64
import os
import string
import random
import hashlib
import urllib.parse
import urllib.request

sys.path.append('..')

try:
    from base.spider import Spider as _Base
except ImportError:
    class _Base:
        pass


# ============================================================ 加密层
# AVBox 1.3.0 只带 lxml/requests/pyquery, 没有 pycryptodome。
# 有 Crypto 用 Crypto(行为一致), 没有就用内置纯 Python 实现。
try:
    from Crypto.PublicKey import RSA as _CRSA
    from Crypto.Cipher import PKCS1_v1_5 as _CPKCS1
    from Crypto.Cipher import AES as _CAES
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False


def _pad(data, block=16):
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def _unpad(data, block=16):
    if not data:
        return data
    n = data[-1]
    if 0 < n <= block and len(data) >= n:
        return data[:-n]
    return data


def _gf_tables():
    alog = [0] * 256
    log = [0] * 256
    x = 1
    for i in range(255):
        alog[i] = x
        log[x] = i
        x ^= ((x << 1) ^ (0x1B if (x & 0x80) else 0)) & 0xFF
    return alog, log


def _mk_sbox():
    alog, log = _gf_tables()
    sbox = [0] * 256
    for i in range(256):
        s = 0 if i == 0 else alog[(255 - log[i]) % 255]
        r = s
        for _ in range(4):
            s = ((s << 1) | (s >> 7)) & 0xFF
            r ^= s
        sbox[i] = r ^ 0x63
    return sbox


_SBOX = _mk_sbox()


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _key_expansion(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_round_key(state, w, rnd):
    for c in range(4):
        kw = w[4 * rnd + c]
        for r in range(4):
            state[r + 4 * c] ^= kw[r]


def _sub_bytes(state):
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _shift_rows(state):
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        for c in range(4):
            state[r + 4 * c] = row[(c + r) % 4]


def _mix_columns(state):
    for c in range(4):
        a = [state[r + 4 * c] for r in range(4)]
        state[0 + 4 * c] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
        state[1 + 4 * c] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
        state[2 + 4 * c] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
        state[3 + 4 * c] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def _aes_encrypt_block(block, w, nr):
    state = list(block)
    _add_round_key(state, w, 0)
    for rnd in range(1, nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, w, rnd)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, w, nr)
    return bytes(state)


class _PureAES(object):
    MODE_ECB = 1
    MODE_CBC = 2

    @classmethod
    def new(cls, key, mode, iv=None):
        return cls(key, mode, iv)

    def __init__(self, key, mode, iv=None):
        if len(key) not in (16, 24, 32):
            raise ValueError('invalid AES key size')
        self.key = bytes(key)
        self.mode = mode
        self.iv = bytes(iv) if iv else b'\x00' * 16
        self._w, self._nr = _key_expansion(self.key)

    def encrypt(self, data):
        out = bytearray()
        prev = self.iv
        for i in range(0, len(data), 16):
            blk = data[i:i + 16]
            if self.mode == _PureAES.MODE_CBC:
                blk = bytes(a ^ b for a, b in zip(blk, prev))
            enc = _aes_encrypt_block(blk, self._w, self._nr)
            out += enc
            prev = enc
        return bytes(out)


def _der_read(buf, i):
    tag = buf[i]
    i += 1
    ln = buf[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[i:i + n], 'big')
        i += n
    return tag, buf[i:i + ln], i + ln


def _rsa_pub_from_der(der):
    tag, seq, _ = _der_read(der, 0)
    if tag != 0x30:
        raise ValueError('bad rsa key')
    i = 0
    _t1, _first, i = _der_read(seq, i)
    if i >= len(seq):
        raise ValueError('bad rsa key')
    t2, second, _ = _der_read(seq, i)
    if t2 == 0x03:
        inner = second[1:]
        _, rs, _ = _der_read(inner, 0)
    elif t2 == 0x30:
        rs = second
    else:
        raise ValueError('bad rsa key')
    j = 0
    _, nb, j = _der_read(rs, j)
    _, eb, _ = _der_read(rs, j)
    return int.from_bytes(nb, 'big'), int.from_bytes(eb, 'big')


class _PurePKCS1(object):
    def __init__(self, key):
        self.n, self.e = key

    def encrypt(self, msg):
        k = (self.n.bit_length() + 7) // 8
        if len(msg) > k - 11:
            raise ValueError('data too long for RSA')
        ps = bytearray()
        while len(ps) < k - len(msg) - 3:
            b = os.urandom(1)
            if b != b'\x00':
                ps += b
        em = b'\x00\x02' + bytes(ps) + b'\x00' + msg
        c = pow(int.from_bytes(em, 'big'), self.e, self.n)
        return c.to_bytes(k, 'big')


if _HAVE_CRYPTO:
    AES = _CAES
    PKCS1_v1_5 = _CPKCS1

    def _rsa_public(der_b64):
        return _CPKCS1.new(_CRSA.import_key(base64.b64decode(der_b64)))
else:
    AES = _PureAES
    PKCS1_v1_5 = _PurePKCS1

    def _rsa_public(der_b64):
        return _PurePKCS1(_rsa_pub_from_der(base64.b64decode(der_b64)))


# ============================================================ 常量
PUB1_B64 = ('MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCr8SzZhjYy+rsya1K09t8d2K50pWFo'
            'BkgUqMpKOiW+3IEVKd4eTdvg9RSOjQ82kypL6R9BnsmrS1V8s4PVDwjQbUtYhTPPC9Hz'
            '16qY7rpD6m0d2vr09/UpWQ5uOy9PR0QTrsioveZ+DIe9jc3C+zBCu/kZSY/R8stwJoiit'
            'ki3gwIDAQAB')
NATIVE_K = b'ed5fdsgucxumegqa'
SAFE = b'OC1A06E197EF10CF3F6058CA7A803B5E'
PW_SAFE = b'11GK2we32144LO&hilUITB)FMd1khdaF'
CERT_MD5 = '6457E81AF1F6D3BC229E33ED60F248A5'
CERT_SHA1 = '8350E6AAEC7A4D8A174377892B4364CFA2066B85'
PKG = 'com.exxammpea.a1'
VC = '3026'
VNAME = '3.0.2.6'
HOST = 'https://gdsaj.hzhcbkj.cn'
UA = 'okhttp/3.12.1'

# 旧站(已停用配置, 可作备用域名重试)
HOST_OLD = 'https://juziapp.hzhcbkj.cn'
PUBLIC_USER = 'fzcrym'

INTRO_PREFIX = "🍊小橙子为您介绍剧情👉请不要相信视频中的广告，以免上当受骗！"


def _mk_safecode():
    try:
        _e = base64.b64encode(AES.new(PW_SAFE, AES.MODE_ECB).encrypt(_pad(
            (CERT_MD5 + '######' + CERT_SHA1 + '~~~~~~' + PKG + '>>>+++' +
             VC).encode(), 16))).decode()
        _e2 = base64.b64encode(_e.encode()).decode()
        return (_e2[:16] + _e2[-16:]).upper()
    except Exception:
        return ''


SAFECODE = _mk_safecode()

# ============================================================ 正则
_RE_TAG = re.compile(r'<[^>]+>')
_RE_EP_NUM = re.compile(r'^第?0*(\d{1,4})[集话期](?:完结)?$')
_RE_MEDIA = re.compile(
    r'(?i)^https?://[^\s]+\.(mp4|m3u8|flv|mkv|avi|ts|mov|mpd|m4a|wmv)(\?.*)?$')
_RE_URL_IN_TEXT = re.compile(
    r'https?://[\x21-\x7e]+?\.(?:m3u8|mp4)(?:\?[\x21-\x7e]*)?', re.I)
_RE_ANY_URL = re.compile(rb'https?://[\x21-\x7e]+')
# 图床/封面地址(4K 线路试解析时解析源会回封面图, 不能当播放地址)
# 含字节 CDN 的 ~tplv-xxx-image.image / .image 后缀写法
_RE_IMG_EXT = re.compile(
    r'(?i)(\.(?:jpg|jpeg|png|webp|gif|bmp|svg|image)(?:\?|$)|'
    r'/+image\.image|tplv-[a-z0-9]+-image)')

_SORT_MAP = {'最新': 'time', '最热': 'hits', '好评': 'score'}
_DEF_FILTERS = {
    '20': ['喜剧', '爱情', '恐怖', '动作', '科幻', '剧情', '战争', '警匪',
           '犯罪', '动画', '奇幻', '武侠', '冒险', '枪战', '悬疑', '惊悚',
           '经典', '青春', '文艺', '微电影', '古装', '历史', '运动', '农村',
           '儿童', '网络电影'],
    '21': ['古装', '战争', '青春', '偶像', '喜剧', '家庭', '犯罪', '动作',
           '奇幻', '剧情', '历史', '经典', '乡村', '情景', '商战', '网剧', '其他'],
    '22': ['真人秀', '脱口秀', '访谈', '选秀', '情感', '旅游', '音乐', '美食',
           '竞技', '益智', '晚会', '游戏'],
    '23': ['冒险', '热血', '奇幻', '恋爱', '搞笑', '治愈', '机战', '校园',
           '运动', '悬疑', '推理', '日常'],
    '24': ['霸总', '逆袭', '甜宠', '穿越', '重生', '复仇', '战神', '萌宝',
           '古装', '都市'],
    '25': ['卫视', '央视', '体育', '影视', '少儿', '纪录', '音乐', '戏曲'],
    '26': ['玄幻', '热血', '恋爱', '搞笑', '冒险', '古风'],
    '27': ['影评', '资讯', '榜单', '花絮'],
}
_CAT_CACHE = {'ts': 0, 'data': None}
_HIST_CACHE = {'ts': 0, 'data': []}
_LINE_CACHE = {'ts': 0, 'data': None}


# ============================================================ 工具
def _clean(s):
    if not s:
        return ''
    s = re.sub(r'<br\s*/?>', '\n', s, flags=re.I)
    s = _RE_TAG.sub('', s)
    s = (s.replace('&nbsp;', ' ').replace('\xa0', ' ')
          .replace('&amp;', '&').replace('&quot;', '"')
          .replace('&#39;', "'").replace('&lt;', '<').replace('&gt;', '>'))
    s = re.sub(r'[ \t\r\f\v]+', ' ', s)
    s = re.sub(r'\n{2,}', '\n', s)
    return s.strip()


def _norm_ep(title):
    if not title:
        return ''
    m = _RE_EP_NUM.match(str(title).strip())
    return m.group(1) if m else str(title).strip()


# 线路权重: 越小越靠前 (直链蓝光优先, 网页解析源靠后)
_LINE_RANK = (('自营', 0), ('超高清', 0), ('4K', 1), ('蓝光', 2),
              ('VIP', 3), ('神话', 4), ('自建', 5), ('HD', 6), ('高清', 6))
# B站/腾讯/优酷/爱奇艺 等正片网页站, 需要播放器内置解析
_RE_WEB_SITE = re.compile(
    r'(?i)(bilibili\.com|qq\.com|v\.qq|youku\.com|iqiyi\.com|mgtv\.com|'
    r'le\.com|sohu\.com|1905\.com)')
# 纯站代号线路(无"蓝光/HD"等字样), 基本都是要网页解析的官方源
_WEB_LINE_CODE = ('BL', 'QQ', 'YK', 'QY', 'MG', 'IQY', 'SOHU', 'B站')
_RE_NEED_Q = re.compile(r'[\u4e00-\u9fa5\s]')


def _line_rank(name):
    n = str(name or '').strip()
    if n in _WEB_LINE_CODE or n.upper() in _WEB_LINE_CODE:
        return 9
    for key, r in _LINE_RANK:
        if key in n:
            return r
    return 7


def _q_url(u):
    """中文/空格路径做百分号编码, 否则播放器请求会 404"""
    if not u or not _RE_NEED_Q.search(u):
        return u
    try:
        sp = urllib.parse.urlsplit(u)
        p = urllib.parse.quote(sp.path, safe="/%:@&=+$,~!*'()")
        q = urllib.parse.quote(sp.query, safe="=&%/:@+$,~!*'()")
        return urllib.parse.urlunsplit((sp.scheme, sp.netloc, p, q, sp.fragment))
    except Exception:
        return u


def _split_list(s):
    if not s:
        return []
    if isinstance(s, (list, tuple)):
        return [str(x).strip() for x in s if str(x).strip()]
    return [x.strip() for x in re.split(r'[,，/|]', str(s)) if x.strip()]


def _varint(n):
    b = b''
    while True:
        x = n & 0x7f
        n >>= 7
        if n:
            b += bytes([x | 0x80])
        else:
            return b + bytes([x])


def _f(num, wire, payload):
    t = _varint((num << 3) | wire)
    if wire == 2:
        return t + _varint(len(payload)) + payload
    return t + payload


def _pb(buf):
    """标准 protobuf 解析: tag 按 varint 读, 支持 fn>15 (如 29 = 0xEA 0x01)"""
    out = []
    i = 0
    n = len(buf)
    while i < n:
        tag = 0
        sh = 0
        while i < n:
            x = buf[i]
            i += 1
            tag |= (x & 0x7f) << sh
            sh += 7
            if not x & 0x80:
                break
        fn, wt = tag >> 3, tag & 7
        if fn == 0:
            break
        if wt == 0:
            v = 0
            sh = 0
            while i < n:
                x = buf[i]
                i += 1
                v |= (x & 0x7f) << sh
                sh += 7
                if not x & 0x80:
                    break
            out.append((fn, wt, v))
        elif wt == 2:
            ln = 0
            sh = 0
            while i < n:
                x = buf[i]
                i += 1
                ln |= (x & 0x7f) << sh
                sh += 7
                if not x & 0x80:
                    break
            out.append((fn, wt, buf[i:i + ln]))
            i += ln
        elif wt == 5:
            out.append((fn, wt, buf[i:i + 4]))
            i += 4
        elif wt == 1:
            out.append((fn, wt, buf[i:i + 8]))
            i += 8
        else:
            i += 1
    return out


def _rnd(k):
    CH = string.ascii_letters + string.digits
    return ''.join(random.sample(list(CH), k - 1)) + '='


def _pic_from(v):
    cands = []
    for _f3, w3, v3 in _pb(v):
        if w3 == 2:
            t = v3.decode('utf-8', 'replace')
            if t.startswith('http'):
                cands.append(t)
    if cands:
        return next((u for u in cands if u.startswith('https')), cands[0])
    return ''


class Spider(_Base):
    HOST_NAME = '橘汁视频'

    _cur_id = ''

    # ---------------------------------------------------- 生命周期
    def getName(self):
        return '橘汁视频'

    def init(self, extend=''):
        """只做本地初始化: 不联网、不抛异常 (AVBox 实例化阶段最忌抛错)"""
        try:
            self.extend = extend or ''
            self.site_url = HOST
            try:
                if isinstance(extend, str) and extend.strip().startswith('{'):
                    j = json.loads(extend)
                elif isinstance(extend, dict):
                    j = extend
                else:
                    j = {}
                if j.get('site'):
                    self.site_url = str(j['site']).rstrip('/')
            except Exception:
                pass
            self.udid = hashlib.md5(
                str(time.time()).encode()).hexdigest()[:16].upper()
            self._rsa1 = _rsa_public(PUB1_B64)
            self._rsa2 = None
            self._token = ''
            self._ready = False
            self._tried = False
            self._last_try = 0
            self._host_idx = 0
            self._play_cache = {}
        except Exception:
            self.udid = '0000000000000000'
            self._rsa1 = None
            self._rsa2 = None
            self._token = ''
            self._ready = False
            self._tried = True
            self._last_try = 0
            self._host_idx = 0
            self._play_cache = {}

    def destroy(self):
        try:
            self._ready = False
            self._tried = True
        except Exception:
            pass

    def close(self):
        self.destroy()

    def isVideoFormat(self, url):
        return True

    def isTextFormat(self, url):
        return False

    def localProxy(self, url):
        try:
            return url
        except Exception:
            return None

    def liveContent(self, filter=False):
        return {'list': []}

    def log(self, *a):
        try:
            print('[juzhi]', *a)
        except Exception:
            pass

    # ---------------------------------------------------- 网络
    def _http(self, url, data=None, headers=None):
        import ssl
        req = urllib.request.Request(url, data=data, headers=headers or {})
        ctx = ssl._create_unverified_context()
        return urllib.request.urlopen(req, timeout=25, context=ctx).read()

    def _hosts(self):
        return [self.site_url, HOST, HOST_OLD]

    # ---------------------------------------------------- 握手
    def _ensure(self):
        """懒加载: 登录 + 取二级公钥; 失败 60s 后可重试"""
        try:
            if self._ready and self._rsa2 is not None:
                return True
            now = int(time.time())
            if self._tried and now - self._last_try < 60:
                return False
            self._tried = True
            self._last_try = now
            seen = set()
            for base in self._hosts():
                if not base or base in seen:
                    continue
                seen.add(base)
                try:
                    self._login(base)
                    if self._zone(base):
                        self.site_url = base
                        self._ready = True
                        self.log('握手成功: %s token=%s' %
                                 (base, '有' if self._token else '无'))
                        return True
                except Exception as e:
                    self.log('握手失败 %s -> %s' % (base, e))
            self.log('全部域名握手失败, 走兜底通道')
        except Exception:
            self._ready = False
        return bool(self._ready)

    def _login(self, base):
        try:
            body = json.dumps({
                'username': 'tv_%s' % self.udid[:10].lower(),
                'password': hashlib.md5(
                    ('tv' + self.udid).encode()).hexdigest(),
                'udid': self.udid}).encode()
            try:
                self._http(base + '/api/ex/v3/user/register', body, {
                    'User-Agent': UA, 'Content-Type': 'application/json'})
            except Exception:
                pass
            d = self._http(base + '/api/ex/v3/user/login', body, {
                'User-Agent': UA, 'Content-Type': 'application/json'})
            data = json.loads(d).get('data') or {}
            tok = data.get('token') or (data.get('user') or {}).get('token') or ''
            if tok:
                self._token = tok
        except Exception:
            pass

    def _zone(self, base):
        try:
            if self._rsa1 is None:
                self._rsa1 = _rsa_public(PUB1_B64)
            ts = int(time.time() * 1000)
            rnd = _rnd(16)
            sign = base64.b64encode(
                self._rsa1.encrypt((str(ts) + rnd).encode())).decode()
            body = (_f(1, 0, _varint(ts)) + _f(2, 2, sign.encode()) +
                    _f(3, 2, rnd.encode()) + _f(4, 2, rnd.encode()) +
                    _f(5, 2, rnd.encode()))
            P = {'plat': 'tv', 'vOs': '16', '_vOsCode': '36', 'vApp': VC,
                 'vName': VNAME, 'pkg': PKG,
                 'appName': '%E6%A9%98%E6%B1%81',
                 'udid': self.udid, 'uuid': self.udid, 'chid': '10000',
                 'androidID': self.udid, 'net': '1', 'young': 0,
                 'tenantId': '*', 'v': 1, 'device': 0, 'lang': 'zh',
                 'country': 'CN', 'cpu': 'arm64-v8a'}
            d = self._http(base + '/api/v5/find/app/zone', body, {
                'User-Agent': UA, 'Content-Type': 'application/x-protobuf',
                'Accept': 'application/x-protobuf',
                'Cache-Control': 'no-cache',
                'publicParams': json.dumps(P, separators=(',', ':'))})
            top = _pb(d)
            code = [v for fn, wt, v in top if fn == 1 and wt == 0]
            c = code[0] if code else 0
            inner = [v for fn, wt, v in top if fn == 3 and wt == 2]
            if c != 200 or not inner:
                msg = [v for fn, wt, v in top if fn == 2 and wt == 2]
                self.log('  zone %s code=%s msg=%s' % (
                    base, c,
                    msg[0].decode('utf-8', 'replace') if msg else ''))
                return False
            strs = {fn: v for fn, wt, v in _pb(inner[0]) if wt == 2}
            # 官方 APK 实测(2024-11 新站): 字段号从 1 起, 1/2/3/4/5 依次拼接
            #   fn1=MIGfMA0GCSqGSIb  fn2=3DQEBAQUAA4GNADC  fn3=16位随机段
            #   fn4=BiQKBgQC…(模数开头) fn5=…IDAQAB(结尾)
            cands = []
            for order in ((1, 2, 3, 4, 5), (1, 2, 4, 5), (2, 3, 4, 5),
                          (1, 3, 4, 5), (1, 4, 5)):
                try:
                    cands.append([strs[i] for i in order])
                except Exception:
                    continue
            for blobs in cands:
                try:
                    b64 = b''.join(blobs).decode('utf-8', 'replace')
                    b64 = re.sub(r'\s+', '', b64)
                    self._rsa2 = _rsa_public(b64)
                    if self._rsa2 is not None:
                        self.log('  二级公钥就绪 (字段 %s)' % (len(blobs),))
                        return True
                except Exception:
                    continue
            return False
        except Exception as e:
            self.log('  zone 异常: %s' % e)
            self._rsa2 = None
            return False

    # ---------------------------------------------------- 请求封装
    def _hdr(self):
        ts = int(time.time() * 1000)
        rnd = _rnd(16)
        sig = ''
        if self._rsa2 is not None:
            try:
                sig = base64.b64encode(
                    self._rsa2.encrypt((str(ts) + rnd + VC).encode())).decode()
            except Exception:
                sig = ''
        try:
            ao = base64.b64encode(AES.new(SAFE, AES.MODE_ECB).encrypt(
                _pad((str(ts) + rnd).encode(), 16))).decode()
        except Exception:
            ao = ''
        J = {'country': 'CN', 'vName': VNAME, 'cpuId': '', 'young': 0,
             'facturer': 'OnePlus', 'pkg': PKG, 'uuid': self.udid,
             'resolution': '1080x2256', 'mac': '02%3A00%3A00%3A00%3A00',
             'sig': sig, 'abid': '7470', 'model': 'PJX110', 'plat': 'tv',
             'udid': self.udid, 'dpi': '480', 'net': '1', 'lang': 'zh',
             'random_str': rnd, 'brand': 'OnePlus', 'timestamp': ts,
             'density': '3.0', 'appName': '%E6%A9%98%E6%B1%81',
             'cpu': 'arm64-v8a', 'chid': '10000',
             'carrier': '%E8%81%94%E9%80%9A',
             'sig2': ao[:8], 'v': 1, 'sig3': ao[8:], 'tenantId': '*',
             '_vOsCode': '36', 'vOs': '16', 'vApp': VC, 'device': 0,
             'androidID': self.udid}
        h = {'User-Agent': UA, 'Accept': 'application/json',
             'Cache-Control': 'no-cache',
             'publicParams': json.dumps(J, separators=(',', ':'),
                                        ensure_ascii=False)}
        if self._token:
            h['token'] = self._token
        return h

    def _secure_map(self, param):
        """map 直传通道: 'k=v&k=v' + ts -> AES(SAFECODE) 单层"""
        ts = int(time.time() * 1000)
        rnd = _rnd(16)
        try:
            ct = AES.new(SAFECODE.encode(), AES.MODE_ECB).encrypt(
                _pad((param + str(ts)).encode(), 16))
        except Exception:
            return b''
        b64 = base64.b64encode(ct).decode()
        return (_f(1, 2, (rnd + b64[:4]).encode()) +
                _f(2, 2, b64[4:].encode()) +
                _f(3, 2, _rnd(20).encode()) +
                _f(4, 0, _varint(ts)) +
                _f(5, 2, rnd.encode()))

    def _secure(self, mapkv):
        """proto/v5 通道: 双层 AES(SAFE->SAFECODE) + 'query=' 前缀, 再外层 AES(SAFECODE)"""
        try:
            e1 = base64.b64encode(AES.new(SAFE, AES.MODE_ECB).encrypt(
                _pad(mapkv.encode(), 16))).decode()
            e2 = base64.b64encode(
                AES.new(SAFECODE.encode(), AES.MODE_ECB).encrypt(
                    _pad(e1.encode(), 16))).decode()
        except Exception:
            return self._secure_map(mapkv)
        payload = 'query=' + e2
        ts = int(time.time() * 1000)
        rnd16 = _rnd(16)
        try:
            ct = AES.new(SAFECODE.encode(), AES.MODE_ECB).encrypt(
                _pad((payload + str(ts)).encode(), 16))
        except Exception:
            return b''
        b64 = base64.b64encode(ct).decode()
        return (_f(1, 2, (rnd16 + b64[:4]).encode()) +
                _f(2, 2, b64[4:].encode()) +
                _f(3, 2, _rnd(20).encode()) +
                _f(4, 0, _varint(ts)) +
                _f(5, 2, rnd16.encode()))

    def _dec_data(self, data):
        """ex/v3 响应 data: SAFECODE 解一层 -> SAFE 解一层 -> JSON"""
        try:
            if not data or not isinstance(data, str):
                return data
            r1 = _unpad(AES.new(SAFECODE.encode(), AES.MODE_ECB).decrypt(
                base64.b64decode(data)))
            r2 = _unpad(AES.new(SAFE, AES.MODE_ECB).decrypt(
                base64.b64decode(r1)))
            return json.loads(r2.decode('utf-8', 'replace'))
        except Exception:
            return None

    def _proto(self, path, qs, mode='map'):
        """
        mode='map'   : _secure_map  (category / getDetail / search / videoUsableUrl)
        mode='query' : _secure     (双层 + query= 前缀)
        返回 (code, data_bytes)
        """
        if self._rsa2 is None:
            return 0, b''
        for mode_try in ([mode, 'query' if mode == 'map' else 'map']
                         if mode else ['map', 'query']):
            try:
                hh = self._hdr()
                hh['Content-Type'] = 'application/x-protobuf'
                hh['Accept'] = 'application/x-protobuf'
                body = (self._secure_map(qs) if mode_try == 'map'
                        else self._secure(qs))
                d = self._http(self.site_url + path, body, hh)
                top = _pb(d)
                code = [v for fn, wt, v in top if fn == 1 and wt == 0]
                c = code[0] if code else 0
                datas = [v for fn, wt, v in top if fn == 3 and wt == 2]
                if c == 200 and datas:
                    if mode_try != mode:
                        self.log('  通道适配: %s -> %s' % (mode, mode_try))
                    return c, datas[0]
                if c not in (0, 200):
                    msg = [v for fn, wt, v in top if fn == 2 and wt == 2]
                    self.log('  proto %s[%s] code=%s msg=%s' % (
                        path.rsplit('/', 1)[-1], mode_try, c,
                        msg[0].decode('utf-8', 'replace')[:40] if msg else ''))
                    if c in (100004, 100003, 400):
                        continue
                    return c, b''
            except Exception as e:
                self.log('  proto %s[%s] FAIL %s' % (path, mode_try, e))
        return 0, b''

    def _json(self, url, headers=None):
        try:
            h = {'User-Agent': UA, 'Accept': 'application/json'}
            if headers:
                h.update(headers)
            return json.loads(self._http(url, None, h))
        except Exception as e:
            self.log('JSON FAIL %s -> %s' % (url, e))
            return {}

    # ---------------------------------------------------- 分类 / 筛选
    def _load_cats(self):
        now = time.time()
        if _CAT_CACHE['data'] and now - _CAT_CACHE['ts'] < 3600:
            return _CAT_CACHE['data']
        cats = []
        for base in self._hosts()[:2]:
            j = self._json(base + '/api/v3/drama/getCategory?orderBy=type_id')
            for c in (j.get('data') or []):
                tid = str(c.get('id') or '')
                if not tid or tid == '29':
                    continue
                raw = c.get('converUrl') or ''
                filt = {}
                if raw:
                    try:
                        filt = json.loads(raw)
                        if isinstance(filt, str):
                            filt = json.loads(filt)
                    except Exception:
                        filt = {}
                cats.append({'type_id': tid,
                             'type_name': c.get('name') or tid,
                             'filter': filt or {}})
            if cats:
                break
        if not cats:
            cats = [{'type_id': t, 'type_name': n, 'filter': {}}
                    for t, n in [('20', '电影'), ('21', '剧集'), ('22', '综艺'),
                                 ('23', '动漫'), ('24', '短剧'), ('25', '直播'),
                                 ('26', '漫剧'), ('27', '')]]
        _CAT_CACHE['data'] = cats
        _CAT_CACHE['ts'] = now
        return cats

    def _build_filters(self, filt, tid):
        out = []
        spec = [('class', '类型'), ('area', '地区'), ('lang', '语言'),
                ('year', '年份'), ('star', '主演'), ('director', '导演'),
                ('state', '状态'), ('version', '版本')]
        for key, name in spec:
            vals = _split_list(filt.get(key))
            if not vals and key == 'class':
                vals = _DEF_FILTERS.get(tid) or []
            if not vals:
                continue
            out.append({'key': key, 'name': name,
                        'value': [{'n': '全部', 'v': ''}] +
                                 [{'n': x, 'v': x} for x in vals]})
        sorts = _split_list(filt.get('extend_sort')) or ['最新', '最热', '好评']
        out.append({'key': 'sort', 'name': '排序',
                    'value': [{'n': s, 'v': _SORT_MAP.get(s, s)}
                              for s in sorts]})
        return out

    def homeContent(self, filter=False):
        try:
            cats = self._load_cats()
            classes = [{'type_id': c['type_id'], 'type_name': c['type_name']}
                       for c in cats]
            classes.append({'type_id': 'history', 'type_name': ''})
            filters = {c['type_id']: self._build_filters(c['filter'],
                                                         c['type_id'])
                       for c in cats}
            self.log('首页分类: %d 个' % len(classes))
            return {'class': classes, 'filters': filters}
        except Exception as e:
            self.log('homeContent 失败: %s' % e)
            return {'class': [{'type_id': 'history', 'type_name': ''}],
                    'filters': {}}

    def homeVideoContent(self):
        try:
            if self._ensure():
                vids = self._list('page=1&pagesize=24')
                if vids:
                    self.log('首页推荐(线上): %d 条' % len(vids))
                    return {'list': vids}
            vids = self._history_list()
            self.log('首页推荐(兜底): %d 条' % len(vids))
            return {'list': vids}
        except Exception:
            return {'list': []}

    # ---------------------------------------------------- 列表
    def _list(self, qs):
        out = []
        code, data = self._proto('/api/proto/v5/drama/category', qs)
        if code != 200 or not data:
            return out
        for fn, wt, v in _pb(data):
            if fn != 1 or wt != 2:
                continue
            info = {'vod_id': '', 'vod_name': '', 'vod_pic': '',
                    'vod_remarks': '', 'vod_year': '', 'vod_area': '',
                    'vod_director': '', 'vod_actor': ''}
            for f2, w2, v2 in _pb(v):
                if f2 == 3 and w2 == 0:
                    info['vod_id'] = str(v2)
                elif f2 == 5 and w2 == 2:
                    info['vod_name'] = v2.decode('utf-8', 'replace')
                elif f2 == 2 and w2 == 2:
                    info['vod_pic'] = _pic_from(v2)
                elif f2 == 13 and w2 == 2:
                    info['vod_remarks'] = v2.decode('utf-8', 'replace')
                elif f2 == 14 and w2 == 0:
                    info['vod_year'] = str(v2)
                elif f2 == 1 and w2 == 2:
                    info['vod_area'] = v2.decode('utf-8', 'replace')
                elif f2 == 7 and w2 == 2:
                    info['vod_director'] = _clean(
                        v2.decode('utf-8', 'replace'))
                elif f2 == 12 and w2 == 2:
                    info['vod_actor'] = _clean(
                        v2.decode('utf-8', 'replace')).lstrip(' ,')
            if info['vod_id'] and info['vod_name']:
                out.append(info)
        return out

    def categoryContent(self, tid, pg, filter=False, extend=None):
        try:
            page = int(pg or 1)
        except Exception:
            page = 1
        try:
            if str(tid) == 'history':
                vids = self._history_list()
                return {'list': vids, 'page': 1, 'pagecount': 1,
                        'limit': len(vids) or 40, 'total': len(vids)}

            if isinstance(extend, str):
                try:
                    extend = json.loads(extend)
                except Exception:
                    extend = {}
            extend = extend or {}
            for k in list(extend.keys()):
                if extend[k] in ('', None, '全部'):
                    del extend[k]
            self.log('category: tid=%s pg=%s ext=%s' % (tid, page, extend))

            parts = ['page=%d' % page, 'pagesize=24', 'typeId1=%s' % tid]
            for k in ('class', 'area', 'lang', 'year', 'star', 'director',
                      'state', 'version'):
                if extend.get(k):
                    parts.append('%s=%s' % (k, urllib.parse.quote(extend[k])))
            if extend.get('sort'):
                parts.append('orderBy=%s' % extend['sort'])
            qs = '&'.join(parts)

            vids = []
            if self._ensure():
                vids = self._list(qs)
            if not vids:
                vids = self._history_list()
                self.log('  列表兜底(观看记录): %d 条' % len(vids))
                return {'list': vids, 'page': 1, 'pagecount': 1,
                        'limit': len(vids) or 24, 'total': len(vids)}
            return {'list': vids, 'page': page, 'pagecount': 999,
                    'limit': 24, 'total': 99999}
        except Exception as e:
            self.log('categoryContent 失败: %s' % e)
            return {'list': [], 'page': 1, 'pagecount': 1,
                    'limit': 24, 'total': 0}

    # ---------------------------------------------------- 观看记录
    def _history_raw(self):
        now = time.time()
        if _HIST_CACHE['data'] and now - _HIST_CACHE['ts'] < 180:
            return _HIST_CACHE['data']
        data = []
        for base in self._hosts()[:2]:
            j = self._json('%s/api/ex/v3/user/history?username=%s' % (
                base, PUBLIC_USER))
            raw = j.get('data')
            if isinstance(raw, str):     # 可能被加密
                raw = self._dec_data(raw) or []
            if raw:
                data = raw
                break
        _HIST_CACHE['data'] = data
        _HIST_CACHE['ts'] = now
        return data

    def _history_list(self):
        out = []
        for it in self._history_raw():
            name = it.get('videoName') or ''
            if not name:
                continue
            frm = (it.get('videoId') or '').split('|')[0] or '正片'
            ep = it.get('videoPart') or ''
            vid = it.get('videoUrl') or ''
            did = it.get('videoDramaId') or 0
            out.append({
                'vod_id': 'h$%s$%s$%s$%s' % (did, frm, ep, vid),
                'vod_name': name,
                'vod_pic': it.get('videoCover') or '',
                'vod_remarks': ('%s·第%s集' % (frm, ep)) if ep else frm,
            })
        return out

    # ---------------------------------------------------- 详情
    def detailContent(self, ids):
        try:
            ids = list(ids or [])
        except Exception:
            ids = []
        if not ids:
            return {'list': []}
        vod_id = str(ids[0])
        self._cur_id = vod_id
        self.log('detail: %s' % vod_id)

        if vod_id.startswith('h$'):
            return {'list': [self._detail_history(vod_id)]}

        out = {'vod_id': vod_id}
        try:
            if not self._ensure():
                raise ValueError('未握手')
            code, data = self._proto('/api/proto/v5/drama/getDetail',
                                     'id=' + vod_id)
            if code != 200 or not data:
                raise ValueError('detail code=%s' % code)
            eps = self._parse_detail(data, out)
            if eps:
                lines, order = {}, []
                for line, t, u in eps:
                    if line not in lines:
                        lines[line] = []
                        order.append(line)
                    lines[line].append('%s$%s' % (_norm_ep(t) or '正片', u))
                # 只有 1 条播放项的线路(短剧"全集"/单片)统一显示为「正片」,
                # 并在线路名后加集数提示, 避免 TVBox 只显示 "1"
                for nm in order:
                    if len(lines[nm]) == 1:
                        t, u = lines[nm][0].split('$', 1)
                        if t in ('1', '', '正片'):
                            lines[nm][0] = '正片$' + u
                order.sort(key=lambda nm: (_line_rank(nm), len(nm), nm))
                out['vod_play_from'] = '$$$'.join(order)
                out['vod_play_url'] = '$$$'.join('#'.join(lines[nm])
                                                 for nm in order)
                # 备注: 优先站点原始备注, 缺失时才用解析到的条数推算
                if not out.get('vod_remarks'):
                    mx = max([len(lines[nm]) for nm in order] or [0])
                    out['vod_remarks'] = ('共%d集' % mx) if mx > 1 else '正片'
            else:
                out['vod_play_from'] = '橘汁'
                out['vod_play_url'] = '暂无片源$http://'
                out['vod_remarks'] = out.get('vod_remarks') or '暂无片源'
        except Exception as e:
            self.log('  详情失败: %s' % e)
            out['vod_name'] = out.get('vod_name') or vod_id
            out['vod_play_from'] = '橘汁'
            out['vod_play_url'] = '暂无片源$http://'
            out['vod_remarks'] = '暂无片源'

        content = _clean(out.get('vod_content', ''))
        out['vod_content'] = (INTRO_PREFIX + '\n' + content) if content \
            else INTRO_PREFIX
        for k in ('vod_name', 'vod_pic', 'vod_remarks', 'vod_director',
                  'vod_actor', 'vod_area', 'vod_year', 'vod_note'):
            out.setdefault(k, '')
        self.log('  详情: %s | %s' % (out.get('vod_name'),
                                     out.get('vod_remarks')))
        return {'list': [out]}

    def _parse_detail(self, data, out):
        """fn 映射: 1地区 2图 6简介 9名 12导演 16/25主演 18年份 26备注 28注 29分集"""
        eps = []
        for fn, wt, v in _pb(data):
            if wt == 2 and fn == 29:
                ep = {}
                for f3, w3, v3 in _pb(v):
                    if w3 == 2:
                        ep[f3] = v3.decode('utf-8', 'replace')
                if ep.get(4):
                    eps.append(ep)
                continue
            if wt != 2:
                if fn == 18 and 'vod_year' not in out:
                    out['vod_year'] = str(v)
                continue
            if fn == 9 and 'vod_name' not in out:
                out['vod_name'] = v.decode('utf-8', 'replace')
            elif fn == 1 and 'vod_area' not in out:
                out['vod_area'] = v.decode('utf-8', 'replace')
            elif fn == 2 and 'vod_pic' not in out:
                out['vod_pic'] = _pic_from(v)
            elif fn == 6 and 'vod_content' not in out:
                out['vod_content'] = _clean(v.decode('utf-8', 'replace'))
            elif fn == 12 and 'vod_director' not in out:
                out['vod_director'] = _clean(v.decode('utf-8', 'replace'))
            elif fn == 16 and 'vod_actor' not in out:
                out['vod_actor'] = _clean(
                    v.decode('utf-8', 'replace')).lstrip(' ,')
            elif fn == 25 and 'vod_actor' not in out:
                out['vod_actor'] = _clean(v.decode('utf-8', 'replace'))
            elif fn == 26 and 'vod_remarks' not in out:
                out['vod_remarks'] = _clean(v.decode('utf-8', 'replace'))
            elif fn == 28 and 'vod_note' not in out:
                out['vod_note'] = _clean(v.decode('utf-8', 'replace'))

        result = []
        for ep in eps:
            title = ep.get(2) or ep.get(3) or ''
            pth = ep.get(4) or ''
            src = ep.get(9) or ''
            src_cn = ep.get(10) or ''
            line = src_cn or src or '正片'
            if _RE_MEDIA.match(pth):
                ep_url = _q_url(pth)
            else:
                ep_url = base64.b64encode(json.dumps(
                    {'vodPlayFrom': src, 'playUrl': pth},
                    separators=(',', ':')).encode()).decode()
            result.append((line, title, ep_url))
        return result

    def _detail_history(self, vod_id):
        p = vod_id.split('$')
        did = p[1] if len(p) > 1 else ''
        frm = p[2] if len(p) > 2 else '正片'
        ep = p[3] if len(p) > 3 else ''
        vid = p[4] if len(p) > 4 else ''
        name, pic = '继续观看', ''
        lines, order = {}, []
        for it in self._history_raw():
            if str(it.get('videoUrl') or '') != vid:
                continue
            if it.get('videoName'):
                name, pic = it['videoName'], it.get('videoCover') or ''
            ln = (it.get('videoId') or '').split('|')[0] or '正片'
            if ln not in lines:
                lines[ln] = []
                order.append(ln)
            lines[ln].append('%s$%s' % (
                _norm_ep(it.get('videoPart') or '正片'),
                it.get('videoUrl') or ''))
        if not lines:
            lines = {frm or '正片': ['%s$%s' % (_norm_ep(ep) or '正片', vid)]}
            order = [frm or '正片']

        # 试解析直链 (线路解析源)
        best = ''
        if self._ensure():
            for ln in order:
                for l in self._play_lines():
                    if l['name'] == ln or l['key'] == ln:
                        best = self._parse_play(l, vid)
                        if best:
                            break
                if best:
                    break

        segs = []
        for ln in order:
            items = []
            for it in lines[ln]:
                t, u = it.split('$', 1)
                items.append('%s$%s' % (_norm_ep(t), best or u))
            segs.append((ln, '#'.join(items)))

        content = INTRO_PREFIX + '\n'
        content += '线路: %s｜当前: 第%s集｜剧集ID: %s' % (
            frm, ep or '-', did or '-')
        if best:
            content += '\n直链: %s' % best[:120]
        else:
            content += '\n（第三方线路码, 播放器需内置相应解析）'
        return {'vod_id': vod_id, 'vod_name': name, 'vod_pic': pic,
                'vod_remarks': ('第%s集' % ep) if ep else '正片',
                'vod_year': '', 'vod_area': '', 'vod_director': '',
                'vod_actor': '', 'vod_content': content,
                'vod_play_from': '$$$'.join(x[0] for x in segs),
                'vod_play_url': '$$$'.join(x[1] for x in segs)}

    # ---------------------------------------------------- 搜索
    def searchContent(self, key, quick, pg='1'):
        try:
            page = int(pg or 1)
        except Exception:
            page = 1
        out = []
        try:
            if self._ensure():
                # 注意: searchKeys 必须传原文(不要 urlencode), 服务端按原样匹配;
                # 编码后服务端会把 %XX 当字面量, 返回默认推荐列表(含无关条目)
                qs = 'page=%d&pagesize=24&searchKeys=%s' % (page, key)
                code, data = self._proto('/api/proto/v5/drama/search', qs,
                                         mode='map')
                if code == 200 and data:
                    for fn, wt, v in _pb(data):
                        if wt != 2 or fn == 0 or fn > 100:
                            continue
                        item = {'vod_id': '', 'vod_name': '', 'vod_pic': '',
                                'vod_remarks': ''}
                        for f3, w3, v3 in _pb(v):
                            if w3 == 0 and f3 == 3:
                                item['vod_id'] = str(v3)
                            elif w3 == 2 and f3 == 5:
                                item['vod_name'] = v3.decode(
                                    'utf-8', 'replace')
                            elif w3 == 2 and f3 == 2:
                                item['vod_pic'] = _pic_from(v3)
                            elif w3 == 2 and f3 == 13:
                                item['vod_remarks'] = v3.decode(
                                    'utf-8', 'replace')
                        if item['vod_id'] and item['vod_name']:
                            out.append(item)
                    # 服务端会在结果头部混入推荐剧, 客户端按关键词再筛一遍
                    if out and not any(key in it['vod_name'] for it in out):
                        pass
                    elif out:
                        hit = [it for it in out if key in it['vod_name']]
                        if hit:
                            out = hit
        except Exception as e:
            self.log('搜索异常: %s' % e)
        if not out:
            for v in self._history_list():
                if key in v['vod_name']:
                    out.append(v)
        self.log('search %s -> %d 条' % (key, len(out)))
        return {'list': out, 'page': page, 'pagecount': 1,
                'limit': 24, 'total': len(out)}

    def searchContentPage(self, key, quick, pg='1'):
        return self.searchContent(key, quick, pg)

    # ---------------------------------------------------- 播放
    def _play_lines(self):
        now = time.time()
        if _LINE_CACHE['data'] and now - _LINE_CACHE['ts'] < 3600:
            return _LINE_CACHE['data']
        lines = []
        for base in self._hosts()[:2]:
            j = self._json(base + '/api/ex/v3/drama/list')
            raw = j.get('data')
            if isinstance(raw, str):
                raw = self._dec_data(raw) or []
            for it in (raw or []):
                cfgs = []
                try:
                    cfgs = json.loads(it.get('config') or '[]')
                except Exception:
                    cfgs = []
                apis = [c.get('url') for c in cfgs
                        if isinstance(c, dict) and
                        str(c.get('url') or '').startswith('http')]
                if apis:
                    lines.append({'key': it.get('key') or '',
                                  'name': it.get('playerName') or
                                          it.get('key') or '',
                                  'apis': apis})
            if lines:
                break
        if not lines:
            lines = [
                {'key': 'zijianm3u8', 'name': '自建4K-2',
                 'apis': ['https://vip1.hzhcbkj.cn/api/?key='
                          '4d003bfa320423f6a5bf432a59e1f329&url=']},
                {'key': 'NB4K', 'name': '自建4K',
                 'apis': ['http://jzjxbk.hzhcbkj.cn/KZNBJX.php?url=']},
            ]
        _LINE_CACHE['data'] = lines
        _LINE_CACHE['ts'] = now
        return lines

    def _parse_play(self, line, vid):
        for api in (line.get('apis') or []):
            for q in ('%s|%s' % (vid, line.get('name') or ''), vid,
                      '%s|%s' % (line.get('name') or '', vid)):
                try:
                    d = self._http(api + urllib.parse.quote(q, safe=''),
                                   None, {'User-Agent': UA})
                    txt = d.decode('utf-8', 'ignore')
                except Exception:
                    continue
                try:
                    j = json.loads(txt)
                except Exception:
                    j = {}
                if isinstance(j, dict):
                    for k in ('url', 'data', 'playUrl', 'm3u8'):
                        v = j.get(k)
                        if isinstance(v, str) and v.startswith('http'):
                            return v
                        if isinstance(v, dict):
                            for kk in ('url', 'playUrl', 'm3u8'):
                                vv = v.get(kk)
                                if isinstance(vv, str) and vv.startswith('http'):
                                    return vv
                m = _RE_URL_IN_TEXT.search(txt)
                if m:
                    return m.group(0)
        return ''

    def playerContent(self, flag, id, vipFlags=None):
        self.log('player: flag=%s id=%s' % (flag, str(id)[:70]))
        if id and _RE_MEDIA.match(id):
            u = _q_url(id)
            return {'parse': 0, 'playUrl': '', 'url': u,
                    'header': {'User-Agent': UA,
                               'Referer': self.site_url + '/'}}

        now = int(time.time())
        if id in self._play_cache:
            ts, res = self._play_cache[id]
            if now - ts < 600:
                return res

        url = ''
        need_parse = 1
        # 1) base64 播放参数 -> videoUsableUrl
        #    响应结构: fn1=playUrl 回显, fn2=是否可用(1), fn3=?, fn4=?, fn5=parse标记
        #    实测 VIP蓝光 fn5=1 -> 返回的是可用直链(但值是 1 表示"已解析")
        #    自建蓝光 fn5=1 且 fn9/fn10 带 "解析视频地址失败" -> 解析源挂了
        try:
            if id and not id.startswith('http') and '|' not in id:
                jm = json.loads(base64.b64decode(id))
                pf = jm.get('vodPlayFrom', '')
                pu = jm.get('playUrl', '')
                if self._ensure():
                    qs = 'vodPlayFrom=%s&playUrl=%s' % (
                        urllib.parse.quote(pf),
                        urllib.parse.quote(pu, safe=''))
                    code, data = self._proto(
                        '/api/proto/v5/videoUsableUrl', qs)
                    if code == 200 and data:
                        got = ''
                        err = ''
                        for fn, wt, v in _pb(data):
                            if wt != 2:
                                continue
                            t = v.decode('utf-8', 'replace')
                            if fn in (1, 6, 7) and t.startswith('http'):
                                got = t
                            elif fn in (8, 9, 10) and ('失败' in t or '错误' in t):
                                err = t
                        if not got:
                            mm = _RE_ANY_URL.search(data)
                            if mm:
                                cand = mm.group(0).decode('utf-8', 'replace')
                                if not _RE_IMG_EXT.search(cand):
                                    got = cand
                        # 图床/封面地址(4K 线路解析源异常时会回封面图)一律视为失败
                        if got and _RE_IMG_EXT.search(got):
                            self.log('  解析源返回图片, 丢弃: %s' % got[:60])
                            got = ''
                        if got:
                            url = got
                            need_parse = 0 if _RE_MEDIA.match(got) else 1
                        elif err:
                            self.log('  videoUsableUrl: %s' % err[:50])
        except Exception:
            pass

        # 2) 第三方线路码 -> 线路解析源
        if not url and id and '|' not in id and not id.startswith('http'):
            for l in self._play_lines():
                url = self._parse_play(l, id)
                if url:
                    break

        if not url:
            url = id or 'http://'
        url = _q_url(url)
        res = {'parse': 0 if _RE_MEDIA.match(url) else 1,
               'playUrl': '', 'url': url,
               'header': {'User-Agent': UA,
                          'Referer': self.site_url + '/'}}
        self._play_cache[id] = (now, res)
        self.log('  => %s (parse=%d)' % (url[:120], res['parse']))
        return res
