# -*- coding: utf-8 -*-
"""
橘汁视频 juziapp.hzhcbkj.cn | TVBox Python 爬虫 
关键:
  - 华谊同款协议栈: RSA 签名 + AES(paramsData) + 手写 protobuf 编解码
  - 注册/登录拿 token, zone 下发二级 RSA 公钥
  - 分类/搜索/详情/播放全走 protobuf 加密通道
  - 详情页含: 导演/主演/地区/年份/评分/副标题(remarks)
  - 分集归一化("第01集"→"01"), 线路排序(超高清>蓝光>其余)
  - 播放结果 600s 缓存, 历史记录直链回放
"""
import re
import sys
import json
import time
import base64
import string
import random
import hashlib
import urllib.parse

sys.path.append('..')

try:
    from base.spider import Spider as _Base
except ImportError:
    import ssl
    import urllib.request as _ur

    class _Base:
        _UA_GLOBAL = 'okhttp/3.12.1'

        def _http(self, url, data=None, headers=None):
            req = _ur.Request(url, data=data, headers=headers or {})
            ctx = ssl._create_unverified_context()
            return _ur.urlopen(req, timeout=25, context=ctx).read()

        def log(self, *a, **kw):
            try:
                print("[juzhi]", *a)
            except Exception:
                pass

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5, AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:  # 兜底: 环境缺 pycryptodome 时给出明确提示
    raise SystemExit("缺少 pycryptodome: pip3 install pycryptodome")


# ===================== 常量 =====================
HOST = 'https://juziapp.hzhcbkj.cn'
UA = 'okhttp/3.12.1'

PUB1_B64 = ('MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCr8SzZhjYy+rsya1K09t8d2K50pWFo'
            'BkgUqMpKOiW+3IEVKd4eTdvg9RSOjQ82kypL6R9BnsmrS1V8s4PVDwjQbUtYhTPPC9Hz'
            '16qY7rpD6m0d2vr09/UpWQ5uOy9PR0QTrsioveZ+DIe9jc3C+zBCu/kZSY/R8stwJoiit'
            'ki3gwIDAQAB')
NATIVE_K = b'ed5fdsgucxumegqa'                    # paramsData AES-CBC key (key=iv)
SAFE = b'OC1A06E197EF10CF3F6058CA7A803B5E'        # sig2/sig3 AES-ECB key
PW_SAFE = b'11GK2we32144LO&hilUITB)FMd1khdaF'     # safecode 生成 key
CERT_MD5 = '090DA8F91D3F60CC6CB250D86F06FE12'
CERT_SHA1 = '3DADB42485B7F864E766479ADA6B1176D81D8D73'
PKG = 'com.mxj.wylcjbxyx'
VC = '3024'

# safecode: AES(PW_SAFE).b64 -> 再 b64 -> 首尾16位拼接
_e = base64.b64encode(AES.new(PW_SAFE, AES.MODE_ECB).encrypt(pad(
    (CERT_MD5 + '######' + CERT_SHA1 + '~~~~~~' + PKG + '>>>+++' + VC).encode(), 16))).decode()
_e2 = base64.b64encode(_e.encode()).decode()
SAFECODE = (_e2[:16] + _e2[-16:]).upper()

INTRO_PREFIX = "🍊小橙子为您介绍剧情👉请不要相信视频中的广告，以免上当受骗！"

DEFAULT_CATS = [
    {'type_id': '21', 'type_name': '电影'},
    {'type_id': '22', 'type_name': '剧集'},
    {'type_id': '25', 'type_name': '动漫'},
    {'type_id': '26', 'type_name': '综艺'},
    {'type_id': '27', 'type_name': '短剧'},
    {'type_id': '28', 'type_name': '漫剧'},
]

# 筛选(filters) —— 与站点 app 端筛选面板对齐
_SORTS = [{'n': '最近更新', 'v': 'update_time'},
          {'n': '热度最高', 'v': 'play_hot'},
          {'n': '评分最高', 'v': 'douban_score'}]
_AREAS = [{'n': '全部', 'v': ''}, {'n': '中国大陆', 'v': '中国大陆'},
          {'n': '中国香港', 'v': '中国香港'}, {'n': '中国台湾', 'v': '中国台湾'},
          {'n': '美国', 'v': '美国'}, {'n': '韩国', 'v': '韩国'},
          {'n': '日本', 'v': '日本'}, {'n': '英国', 'v': '英国'},
          {'n': '法国', 'v': '法国'}, {'n': '泰国', 'v': '泰国'},
          {'n': '印度', 'v': '印度'}, {'n': '其他', 'v': '其他'}]
_YEARS = [{'n': '全部', 'v': ''}] + \
         [{'n': str(y), 'v': str(y)} for y in range(2026, 1999, -1)]

_FILTERS_MAP = {
    '21': ['全部', '剧情', '喜剧', '动作', '爱情', '科幻', '动画',
           '悬疑', '惊悚', '恐怖', '犯罪', '冒险', '战争', '奇幻',
           '传记', '历史', '武侠', '歌舞', '短片', '纪录片'],
    '22': ['全部', '剧情', '喜剧', '爱情', '都市', '悬疑', '古装',
           '偶像', '家庭', '犯罪', '玄幻', '军事', '谍战', '武侠'],
    '25': ['全部', '冒险', '热血', '奇幻', '恋爱', '搞笑', '治愈',
           '机战', '校园', '运动', '悬疑', '推理', '日常'],
    '26': ['全部', '真人秀', '脱口秀', '访谈', '选秀', '情感', '旅游',
           '音乐', '美食', '竞技', '益智', '晚会', '游戏'],
    '27': ['全部', '霸总', '逆袭', '甜宠', '穿越', '重生', '复仇',
           '战神', '萌宝', '古装', '都市'],
    '28': ['全部', '玄幻', '热血', '恋爱', '搞笑', '冒险', '古风'],
}

FILTERS = {}
for _c in DEFAULT_CATS:
    _tid = _c['type_id']
    FILTERS[_tid] = [
        {'key': 'class', 'name': '类型',
         'value': [{'n': x, 'v': '' if x == '全部' else x}
                   for x in _FILTERS_MAP.get(_tid, ['全部'])]},
        {'key': 'area', 'name': '地区', 'value': _AREAS},
        {'key': 'year', 'name': '年份', 'value': _YEARS},
        {'key': 'orderBy', 'name': '排序', 'value': _SORTS},
    ]

# 副标题(remarks) 归一化别名
_REMARKS_ALIAS = {
    '连载中': '连载中', '完结': '完结', '正片': '正片',
}


# ===================== 正则 =====================
_RE_TAG = re.compile(r'<[^>]+>')
_RE_EP_NUM = re.compile(r'^第?0*(\d{1,4})[集话期](?:完结)?$')
_RE_EP_NUM2 = re.compile(r'^第?0*(\d{1,4})[集话期]$')
_RE_URL = re.compile(rb'https?://[\x21-\x7e]+')
_RE_MEDIA = re.compile(
    r'(?i).*\.(mp4|m3u8|flv|mkv|avi|ts|mov|mpd|m4a|wmv)(\?.*)?$')
_RE_ACTOR_FALLBACK = re.compile(
    r'[\u4e00-\u9fa5·]{2,12}(?::?,)?[一-龥·]{2,12}')


# ===================== 工具函数 =====================
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
    """手写 protobuf 解码: 返回 [(field_number, wire_type, value)]"""
    out = []
    i = 0
    n = len(buf)
    while i < n:
        b = buf[i]
        fn, wt = b >> 3, b & 7
        i += 1
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


def _clean_html(s):
    """去 HTML 标签 + 实体 (豆花风格 _clean)"""
    if not s:
        return ''
    s = _RE_TAG.sub('', s)
    s = (s.replace('&nbsp;', ' ').replace('\xa0', ' ')
          .replace('&amp;', '&').replace('&quot;', '"')
          .replace('&#39;', "'").replace('&lt;', '<').replace('&gt;', '>'))
    s = re.sub(r'[ \t\r\f\v]+', ' ', s)
    s = re.sub(r'\n{2,}', '\n', s)
    return s.strip()


def _norm_ep(title):
    """集名归一化: '第01集'/'第01集完结' -> '01'"""
    if not title:
        return ''
    m = _RE_EP_NUM.match(title.strip())
    if m:
        return m.group(1)
    return title


def _pic_pick(v):
    """海报字段: 内嵌消息里取 http 串, 优先 https"""
    cands = [x.decode('utf-8', 'replace')
             for _, w, x in _pb(v) if w == 2 and x.startswith(b'http')]
    if cands:
        return next((u for u in cands if u.startswith('https')), cands[0])
    return ''


class Spider(_Base):
    HOST_NAME = '橘汁视频'

    _cur_id = ''

    # ---------- 生命周期 ----------
    def getName(self):
        return '橘汁视频'

    def init(self, extend=''):
        try:
            self.extend = json.loads(extend) if extend else {}
        except Exception:
            self.extend = {}
        self.site_url = (self.extend.get('site') or HOST).rstrip('/')
        self.udid = hashlib.md5(str(time.time()).encode()).hexdigest()[:16].upper()
        self._rsa1 = PKCS1_v1_5.new(RSA.import_key(base64.b64decode(PUB1_B64)))
        self._rsa2 = None
        self._token = ''
        self._play_cache = {}
        self._login()
        self._zone()
        self.log('init: site=%s udid=%s token=%s' %
                 (self.site_url, self.udid, '有' if self._token else '无'))

    def destroy(self):
        pass

    def close(self):
        self.destroy()

    def isVideoFormat(self, url):
        return True

    def isTextFormat(self, url):
        return False

    # ---------- 网络与协议 ----------
    def _http(self, url, data=None, headers=None):
        import ssl
        import urllib.request
        req = urllib.request.Request(url, data=data, headers=headers or {})
        ctx = ssl._create_unverified_context()
        return urllib.request.urlopen(req, timeout=25, context=ctx).read()

    def _login(self):
        """注册(忽略失败) + 登录拿 token"""
        try:
            body = json.dumps({
                'username': 'tv_%s' % self.udid[:10].lower(),
                'password': hashlib.md5(('tv' + self.udid).encode()).hexdigest(),
                'udid': self.udid}).encode()
            try:
                self._http(self.site_url + '/api/ex/v3/user/register', body, {
                    'User-Agent': UA, 'Content-Type': 'application/json'})
            except Exception:
                pass
            d = self._http(self.site_url + '/api/ex/v3/user/login', body, {
                'User-Agent': UA, 'Content-Type': 'application/json'})
            data = json.loads(d).get('data') or {}
            self._token = (data.get('token') or
                           (data.get('user') or {}).get('token') or '')
            self.log('登录: token=%s' % (self._token[:12] + '...' if self._token else '空'))
        except Exception as e:
            self.log('登录失败: %s' % e)
            self._token = ''

    def _zone(self):
        """zone 接口下发二级 RSA 公钥 (protobuf fn3 内 fn2/3/4/5 拼接)"""
        try:
            ts = int(time.time() * 1000)
            rnd = _rnd(16)
            sign = base64.b64encode(
                self._rsa1.encrypt((str(ts) + rnd).encode())).decode()
            body = (_f(1, 0, _varint(ts)) + _f(2, 2, sign.encode()) +
                    _f(3, 2, rnd.encode()) + _f(4, 2, rnd.encode()) +
                    _f(5, 2, rnd.encode()))
            P = {'plat': 'android', 'vOs': '16', '_vOsCode': '36', 'vApp': VC,
                 'vName': '3.0.2.4', 'pkg': PKG,
                 'appName': '%E6%A9%98%E6%B1%81',
                 'udid': self.udid, 'uuid': self.udid, 'chid': '10000',
                 'androidID': self.udid, 'net': '1', 'young': 0,
                 'tenantId': '*', 'v': 1, 'device': 0, 'lang': 'zh',
                 'country': 'CN', 'cpu': 'arm64-v8a'}
            d = self._http(self.site_url + '/api/v5/find/app/zone', body, {
                'User-Agent': UA, 'Content-Type': 'application/x-protobuf',
                'Accept': 'application/x-protobuf',
                'Cache-Control': 'no-cache',
                'publicParams': json.dumps(P, separators=(',', ':'))})
            top = _pb(d)
            inner = [v for fn, wt, v in top if fn == 3 and wt == 2][0]
            strs = {fn: v for fn, wt, v in _pb(inner) if wt == 2}
            self._rsa2 = PKCS1_v1_5.new(RSA.import_key(base64.b64decode(
                strs[2] + strs[3] + strs[4] + strs[5])))
            self.log('zone: 二级公钥就绪')
        except Exception as e:
            self.log('zone 失败: %s' % e)
            self._rsa2 = None

    def _hdr(self):
        """构造带 sig/sig2/sig3 的加密请求头"""
        ts = int(time.time() * 1000)
        rnd = _rnd(16)
        sig = ''
        if self._rsa2:
            try:
                sig = base64.b64encode(
                    self._rsa2.encrypt((str(ts) + rnd + VC).encode())).decode()
            except Exception:
                sig = ''
        ao = base64.b64encode(AES.new(SAFE, AES.MODE_ECB).encrypt(
            pad((str(ts) + rnd).encode(), 16))).decode()
        J = {'country': 'CN', 'vName': '3.0.2.4', 'cpuId': '', 'young': 0,
             'facturer': 'OnePlus', 'pkg': PKG, 'uuid': self.udid,
             'resolution': '1080x2256',
             'mac': '02%3A00%3A00%3A00%3A00%3A00',
             'sig': sig, 'abid': '7470', 'model': 'PJX110', 'plat': 'android',
             'udid': self.udid, 'dpi': '480', 'net': '1', 'lang': 'zh',
             'random_str': rnd, 'brand': 'OnePlus', 'timestamp': ts,
             'density': '3.0', 'appName': '%E6%A9%98%E6%B1%81',
             'cpu': 'arm64-v8a', 'chid': '10000',
             'carrier': '%E8%81%94%E9%80%9A',
             'sig2': ao[:8], 'v': 1, 'sig3': ao[8:], 'tenantId': '*',
             '_vOsCode': '36', 'vOs': '16', 'vApp': VC, 'device': 0,
             'androidID': self.udid}
        blob = json.dumps(J, separators=(',', ':'),
                          ensure_ascii=False).encode()
        pd_hex = AES.new(NATIVE_K, AES.MODE_CBC, NATIVE_K).encrypt(
            pad(blob, 16)).hex()
        h = {'User-Agent': UA, 'Accept': 'application/json',
             'Cache-Control': 'no-cache',
             'publicParams': json.dumps({'paramsData': pd_hex},
                                        separators=(',', ':'))}
        if self._token:
            h['token'] = self._token
        return h

    def _secure(self, qs):
        """请求体加密 (protobuf: rnd+b64前12 | b64剩余 | 随机 | ts | rnd)"""
        ts = int(time.time() * 1000)
        rnd8 = _rnd(8)
        plain = (qs + str(ts)).encode()
        ct = AES.new(SAFECODE.encode(), AES.MODE_ECB).encrypt(pad(plain, 16))
        b64 = base64.b64encode(ct).decode()
        return (_f(1, 2, (rnd8 + b64[:12]).encode()) +
                _f(2, 2, b64[12:].encode()) +
                _f(3, 2, _rnd(20).encode()) +
                _f(4, 0, _varint(ts)) +
                _f(5, 2, rnd8.encode()))

    def _proto_post(self, path, qs):
        """加密通道 POST: 返回 (code, data_bytes)"""
        try:
            hh = self._hdr()
            hh['Content-Type'] = 'application/x-protobuf'
            hh['Accept'] = 'application/x-protobuf'
            d = self._http(self.site_url + path, self._secure(qs), hh)
            top = _pb(d)
            code = [v for fn, wt, v in top if fn == 1 and wt == 0]
            datas = [v for fn, wt, v in top if fn == 3 and wt == 2]
            return ((code[0] if code else 0),
                    datas[0] if datas else b'')
        except Exception as e:
            self.log('proto POST FAIL %s -> %s' % (path, e))
            return 0, b''

    # ---------- 首页 ----------
    def homeContent(self, filter=False):
        cats = []
        try:
            d = self._http(
                self.site_url + '/api/v3/drama/getCategory?orderBy=type_id',
                None, {'User-Agent': UA, 'Accept': 'application/json'})
            for c in (json.loads(d).get('data') or []):
                if str(c.get('id')) != '29':  # 29 为隐藏分类, 跳过
                    cats.append({'type_id': str(c['id']),
                                 'type_name': c.get('name', '')})
        except Exception as e:
            self.log('getCategory 失败: %s' % e)
        if not cats:
            cats = [dict(c) for c in DEFAULT_CATS]
        self.log('首页分类: %d 个' % len(cats))
        return {'class': cats, 'filters': FILTERS}

    def homeVideoContent(self):
        return {'list': self._list('page=1&pagesize=24')}

    # ---------- 列表 ----------
    def _vodids(self):
        try:
            d = self._http(self.site_url + '/api/ex/v3/security/tag/list',
                           None, self._hdr())
            tags = json.loads(d).get('data') or []
            ids = []
            for t in tags:
                for sec in (t.get('sections') or []):
                    for v in (sec.get('vodList') or []):
                        ids.append(str(v.get('id')))
            return ','.join(ids[:6])
        except Exception:
            return ''

    def _list(self, qs):
        """分类/首页列表: protobuf fn1=item, f3=id(varint), f5=名, f2=图, f13=备注"""
        out = []
        code, data = self._proto_post('/api/proto/v5/drama/category', qs)
        if code != 200 or not data:
            self.log('  列表 code=%s' % code)
            return out
        for fn, wt, v in _pb(data):
            if fn != 1 or wt != 2:
                continue
            info = {'vod_id': '', 'vod_name': '', 'vod_pic': '',
                    'vod_remarks': ''}
            for f2, w2, v2 in _pb(v):
                if f2 == 3 and w2 == 0:
                    info['vod_id'] = str(v2)
                elif f2 == 5 and w2 == 2:
                    info['vod_name'] = v2.decode('utf-8', 'replace')
                elif f2 == 2 and w2 == 2:
                    info['vod_pic'] = _pic_pick(v2)
                elif f2 == 13 and w2 == 2:
                    info['vod_remarks'] = _REMARKS_ALIAS.get(
                        v2.decode('utf-8', 'replace'),
                        v2.decode('utf-8', 'replace'))
            if info['vod_id'] and info['vod_name']:
                out.append(info)
        self.log('  列表: %d 条 (qs=%s)' % (len(out), qs))
        return out

    def categoryContent(self, tid, pg, filter, extend):
        self.log('category: tid=%s pg=%s extend=%s' % (tid, pg, extend))
        page = int(pg) if pg else 1
        if isinstance(extend, str):
            try:
                extend = json.loads(extend)
            except Exception:
                extend = {}
        if not extend:
            extend = {}
        for k in list(extend.keys()):
            if extend[k] in ('', None, '全部'):
                del extend[k]

        if tid == 'history':
            return {'list': self._history_list(), 'page': 1,
                    'pagecount': 1, 'limit': 40, 'total': 40}

        parts = ['page=%d' % page, 'pagesize=24', 'typeId1=%s' % tid]
        if extend.get('class'):
            parts.append('class=%s' % urllib.parse.quote(extend['class']))
        if extend.get('area'):
            parts.append('area=%s' % urllib.parse.quote(extend['area']))
        if extend.get('year'):
            parts.append('year=%s' % extend['year'])
        if extend.get('orderBy'):
            parts.append('orderBy=%s' % extend['orderBy'])
        qs = '&'.join(parts)

        videos = self._list(qs)
        return {'list': videos, 'page': page, 'pagecount': 999,
                'limit': 24, 'total': 99999}

    def _history_list(self):
        out = []
        try:
            d = self._http(
                self.site_url + '/api/ex/v3/user/history?username=fzcrym',
                None, {'User-Agent': UA, 'Accept': 'application/json'})
            for it in (json.loads(d).get('data') or []):
                vid = it.get('videoId', '')
                if '|' in vid:
                    frm, url = vid.split('|', 1)
                    out.append({
                        'vod_id': 'h$%s$%s' % (frm, url),
                        'vod_name': it.get('videoName', ''),
                        'vod_pic': it.get('videoCover', ''),
                        'vod_remarks': '%s·第%s集' %
                                       (frm, it.get('videoPart', '')),
                    })
        except Exception as e:
            self.log('历史记录失败: %s' % e)
        return out

    # ---------- 搜索 ----------
    def searchContent(self, key, quick, pg='1'):
        page = int(pg) if pg else 1
        self.log('search: key=%s pg=%d' % (key, page))
        try:
            qs = 'page=%d&pagesize=24&searchKeys=%s' % (
                page, urllib.parse.quote(key))
            code, datas = self._proto_post('/api/proto/v5/drama/search', qs)
            if code != 200 or not datas:
                return {'list': [], 'page': page}
            out = []
            for fn, wt, v in _pb(datas):
                if wt != 2 or fn == 0 or fn > 100:
                    continue
                item = {'vod_id': '', 'vod_name': '', 'vod_pic': '',
                        'vod_remarks': ''}
                for f3, w3, v3 in _pb(v):
                    if w3 != 2 and not (f3 == 3 and w3 == 0):
                        continue
                    try:
                        if f3 == 3 and w3 == 0:
                            item['vod_id'] = str(v3)
                        elif f3 == 5 and w3 == 2:
                            item['vod_name'] = v3.decode('utf-8', 'replace')
                        elif f3 == 2 and w3 == 2:
                            item['vod_pic'] = _pic_pick(v3)
                        elif f3 == 13 and w3 == 2:
                            item['vod_remarks'] = v3.decode(
                                'utf-8', 'replace')
                        elif f3 == 4 and w3 == 2:
                            item['vod_content'] = _clean_html(
                                v3.decode('utf-8', 'replace'))[:100]
                    except Exception:
                        pass
                if item['vod_id'] and item['vod_name']:
                    out.append(item)
            self.log('  搜索: %d 条' % len(out))
            return {'list': out, 'page': page}
        except Exception as e:
            self.log('搜索失败: %s' % e)
            return {'list': [], 'page': page}

    def searchContentPage(self, key, quick, pg='1'):
        return self.searchContent(key, quick, pg)

    # ---------- 详情 ----------
    def detailContent(self, ids):
        if not ids:
            return {'list': []}
        vod_id = str(ids[0])
        self._cur_id = vod_id
        self.log('detail: %s' % vod_id)

        # 历史记录直链回放
        if vod_id.startswith('h$'):
            _, frm, url = vod_id.split('$', 2)
            return {'list': [{
                'vod_id': vod_id, 'vod_name': '继续观看',
                'vod_play_from': frm, 'vod_play_url': '正片$%s' % url,
                'vod_pic': '', 'vod_remarks': '历史记录',
                'vod_content': INTRO_PREFIX + '\n播放历史·线路:' + frm}]}

        out = {'vod_id': vod_id}
        try:
            code, data = self._proto_post(
                '/api/proto/v5/drama/getDetail', 'id=' + vod_id)
            if code != 200 or not data:
                raise RuntimeError('detail code=%s' % code)

            dd = _pb(data)
            for fn, wt, v in dd:
                if fn == 0 or fn > 100:
                    break  # protobuf 错位起点, 之后全是字符串碎片(乱码源)
                if fn == 9 and wt == 2 and 'vod_name' not in out:
                    out['vod_name'] = v.decode('utf-8', 'replace')
                elif fn == 1 and wt == 2 and 'vod_area' not in out:
                    out['vod_area'] = v.decode('utf-8', 'replace')
                elif fn == 12 and wt == 2 and 'vod_director' not in out:
                    out['vod_director'] = _clean_html(
                        v.decode('utf-8', 'replace'))
                elif fn == 16 and wt == 2 and 'vod_actor' not in out:
                    out['vod_actor'] = _clean_html(
                        v.decode('utf-8', 'replace')).lstrip(' ,')
                elif fn == 25 and wt == 2 and 'vod_actor' not in out:
                    out['vod_actor'] = _clean_html(
                        v.decode('utf-8', 'replace'))
                elif fn == 6 and wt == 2 and 'vod_content' not in out:
                    out['vod_content'] = _clean_html(
                        v.decode('utf-8', 'replace'))
                elif fn == 2 and wt == 2 and 'vod_pic' not in out:
                    out['vod_pic'] = _pic_pick(v)

            # 演员兜底: f16/f25 无值时从错位块的干净中文串提取
            if 'vod_actor' not in out:
                for fn, wt, v in dd:
                    if fn == 0 and wt == 2:
                        txt = v.decode('utf-8', 'replace')
                        names = _RE_ACTOR_FALLBACK.findall(txt)
                        cand = [x.strip(' ,:·') for x in names
                                if len(x.strip(' ,:·')) >= 4]
                        if cand:
                            out['vod_actor'] = ','.join(cand[:6])
                            break

            # ===== f29 分集: 详情响应 _pb 会错位, 用原始 0xEA01 tag 扫描 =====
            eps = []
            pos = 0
            n = len(data)
            while True:
                j = data.find(b'\xea\x01', pos)
                if j < 0:
                    break
                k = j + 2
                ln = 0
                sh = 0
                while k < n and data[k] & 0x80:
                    ln |= (data[k] & 0x7f) << sh
                    sh += 7
                    k += 1
                if k >= n:
                    break
                ln |= (data[k] & 0x7f) << sh
                k += 1
                if ln <= 0 or k + ln > n:
                    pos = j + 1
                    continue
                entry = data[k:k + ln]
                pos = k + ln
                title = pth = src = src_cn = ''
                for f3_, w3_, v3_ in _pb(entry):
                    if w3_ != 2:
                        continue
                    if f3_ in (2, 3) and not title:
                        title = v3_.decode('utf-8', 'replace')
                    elif f3_ == 4:
                        pth = v3_.decode('utf-8', 'replace')
                    elif f3_ == 9:
                        src = v3_.decode('utf-8', 'replace')
                    elif f3_ == 10:
                        src_cn = v3_.decode('utf-8', 'replace')
                if not pth:
                    continue
                eps.append((_norm_ep(title), pth, src, src_cn))

            self.log('  分集: %d 集' % len(eps))

            # 按线路分组; 非直链的播放参数 base64 封装给 playerContent 解
            lines = {}
            order = []
            for title, pth, src, src_cn in eps:
                line = src_cn or src or '正片'
                if line not in lines:
                    lines[line] = []
                    order.append(line)
                if _RE_MEDIA.match(pth):
                    ep_url = pth
                else:
                    ep_url = base64.b64encode(json.dumps(
                        {'vodPlayFrom': src, 'playUrl': pth},
                        separators=(',', ':')).encode()).decode()
                lines[line].append('%s$%s' % (title or '正片', ep_url))

            # 线路排序: 超高清最前, 蓝光次之, 其余按名殿后
            def _rank(nm):
                if '超高清' in nm:
                    return 0
                if '蓝光' in nm:
                    return 1
                return 2
            order.sort(key=lambda x: (_rank(x), x))

            if order:
                out['vod_play_from'] = '$$$'.join(order)
                out['vod_play_url'] = '$$$'.join(
                    '#'.join(lines[l]) for l in order)
            else:
                out['vod_play_from'] = '橘汁'
                out['vod_play_url'] = '暂无片源$http://'

            out['vod_remarks'] = ('共%d集' % len(eps)) if eps else '暂无片源'
        except Exception as e:
            self.log('详情失败: %s' % e)
            out['vod_name'] = vod_id
            out['vod_play_from'] = '橘汁'
            out['vod_play_url'] = '播放$http://'
            out['vod_remarks'] = ''

        # ===== 简介前缀 (与豆花同款) =====
        content = out.get('vod_content', '')
        if content:
            out['vod_content'] = INTRO_PREFIX + '\n' + content
        else:
            out['vod_content'] = INTRO_PREFIX

        out.setdefault('vod_name', vod_id)
        out.setdefault('vod_pic', '')
        out.setdefault('vod_remarks', '')
        out.setdefault('vod_director', '')
        out.setdefault('vod_actor', '')
        out.setdefault('vod_area', '')
        out.setdefault('vod_year', '')
        return {'list': [out]}

    # ---------- 播放 ----------
    def playerContent(self, flag, id, vipFlags):
        self.log('player: flag=%s id=%s' % (flag, str(id)[:60]))
        url = id
        try:
            if id and not id.startswith('http') and not id.startswith('h$'):
                # base64 封装的播放参数 -> videoUsableUrl 换真实直链
                jm = json.loads(base64.b64decode(id))
                pf, pu = jm.get('vodPlayFrom', ''), jm.get('playUrl', '')

                cache_key = '%s|%s' % (pf, pu)
                now = int(time.time())
                if cache_key in self._play_cache:
                    ts, res = self._play_cache[cache_key]
                    if now - ts < 600:
                        self.log('  命中缓存')
                        return res

                qs = 'vodPlayFrom=%s&playUrl=%s' % (
                    urllib.parse.quote(pf), urllib.parse.quote(pu, safe=''))
                code, data = self._proto_post(
                    '/api/proto/v5/videoUsableUrl', qs)
                if code == 200 and data:
                    mm = _RE_URL.search(data)
                    if mm:
                        url = mm.group(0).decode('utf-8', 'replace')
                self.log('  => %s' % (url[:120] if url.startswith('http')
                                      else '未取到直链'))
                res = {'parse': 0, 'playUrl': '', 'url': url,
                       'header': {'User-Agent': UA}}
                self._play_cache[cache_key] = (now, res)
                return res
            elif not url.startswith('http'):
                url = 'http://'
        except Exception as e:
            self.log('player FAIL: %s' % e)
        return {'parse': 0, 'playUrl': '', 'url': url,
                'header': {'User-Agent': UA}}

    # ---------- 本地代理 (图片防盗链兜底) ----------
    def localProxy(self, param):
        try:
            url = ''
            if isinstance(param, dict):
                url = param.get('url', '')
            else:
                for pair in str(param).split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        if k == 'url':
                            url = v
            if not url:
                return [200, 'image/jpeg', b'', '']
            if '%' in url:
                url = urllib.parse.unquote(url)
            if url.startswith('//'):
                url = 'https:' + url
            import ssl
            import urllib.request
            req = urllib.request.Request(url, headers={'User-Agent': UA})
            ctx = ssl._create_unverified_context()
            rsp = urllib.request.urlopen(req, timeout=15, context=ctx)
            content = rsp.read()
            ctype = rsp.headers.get('Content-Type', 'image/jpeg')
            if not ctype.startswith('image/'):
                ctype = 'image/jpeg'
            return [200, ctype, content, '']
        except Exception:
            return [200, 'image/jpeg', b'', '']
