# coding=utf-8
"""
66大片网 www.66dpw.vip | TVBox Python 爬虫 
关键:
  - 苹果CMS mxpro 模板解析
  - 破解播放页 player_aaaa 的 encrypt=2 地址: base64 -> URL decode
  - 极速线路直出 m3u8 (parse=0), 哔哩哔哩等外链交嗅探 (parse=1)
  - 搜索接口带验证码检测 (返回空并提示)
"""
import re
import sys
import json
import base64
import time
import urllib.parse

sys.path.append('..')

try:
    from base.spider import Spider
except ImportError:
    import requests as _rq
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    class _BaseSpider:
        def __init__(self):
            self._session = None

        @property
        def _sess(self):
            if self._session is None:
                self._session = _rq.Session()
                self._session.verify = False
                adapter = _rq.adapters.HTTPAdapter(
                    pool_connections=10, pool_maxsize=10, max_retries=0)
                self._session.mount('https://', adapter)
                self._session.mount('http://', adapter)
            return self._session

        def fetch(self, url, headers=None, **kw):
            timeout = kw.pop('timeout', 15)
            r = self._sess.get(url, headers=headers, timeout=timeout, **kw)
            r.encoding = 'utf-8'
            return r

        def log(self, *a, **kw):
            try:
                print("[66dpw]", *a)
            except Exception:
                pass

    Spider = _BaseSpider


HOST = "https://www.66dpw.vip"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
DEFAULT_PIC = "https://www.66dpw.vip/template/mxpro/mxtheme/images/logo.png"

INTRO_PREFIX = "🍊小橙子为您介绍剧情👉请不要相信视频中的广告，以免上当受骗！"

CLASSES = [
    {"type_id": "1", "type_name": "电影"},
    {"type_id": "3", "type_name": "剧集"},
    {"type_id": "2", "type_name": "动漫"},
    {"type_id": "5", "type_name": "综艺"},
    {"type_id": "4", "type_name": "短剧"},
]

# 筛选: maccms 内置 /vodtype/{tid}/class/{v}/area/{v}/year/{v}.html
# (无效值服务端会静默降级为全部列表, 安全)
_SORTS = [{"n": "全部", "v": ""}]
_YEARS = [{"n": "全部", "v": ""}] + \
         [{"n": str(y), "v": str(y)} for y in range(2026, 1999, -1)]
_AREAS = [
    {"n": "全部", "v": ""},
    {"n": "中国大陆", "v": "中国大陆"}, {"n": "美国", "v": "美国"},
    {"n": "中国香港", "v": "中国香港"}, {"n": "中国台湾", "v": "中国台湾"},
    {"n": "韩国", "v": "韩国"}, {"n": "日本", "v": "日本"},
    {"n": "英国", "v": "英国"}, {"n": "法国", "v": "法国"},
    {"n": "泰国", "v": "泰国"}, {"n": "印度", "v": "印度"},
    {"n": "其它", "v": "其它"},
]
_CLASSES_ALL = [
    "剧情", "喜剧", "爱情", "动作", "悬疑", "恐怖", "科幻", "奇幻",
    "犯罪", "惊悚", "冒险", "战争", "历史", "古装", "家庭", "纪录",
    "动画", "音乐", "传记", "武侠", "运动", "灾难", "西部", "短片",
]

_FILTERS_MAP = {
    "1": ["全部", "剧情", "喜剧", "爱情", "动作", "惊悚", "犯罪", "恐怖",
          "悬疑", "冒险", "奇幻", "科幻", "家庭", "历史", "战争", "纪录",
          "古装", "音乐", "动画", "传记", "武侠", "运动", "短片"],
    "3": ["全部", "剧情", "喜剧", "爱情", "犯罪", "悬疑", "家庭", "古装",
          "惊悚", "动作", "奇幻", "科幻", "都市", "历史", "战争", "冒险",
          "武侠", "恐怖", "青春", "传记", "情感", "纪录", "军旅"],
    "2": ["全部", "动画", "冒险", "喜剧", "奇幻", "剧情", "科幻", "动作",
          "儿童", "悬疑", "都市", "家庭", "国漫", "日常", "爱情", "玄幻",
          "日漫", "音乐", "治愈", "古风", "校园"],
    "4": ["全部", "剧情", "爱情", "古装", "悬疑", "喜剧", "奇幻", "都市",
          "玄幻", "犯罪", "家庭", "穿越", "惊悚", "武侠", "科幻", "动作",
          "冒险", "恐怖", "青春", "历史"],
    "5": ["全部", "真人秀", "脱口秀", "喜剧", "晚会", "音乐", "纪录",
          "游戏", "生活", "文化", "情感", "美食", "竞技"],
}

FILTERS = {}
for _tid in ["1", "3", "2", "4", "5"]:
    FILTERS[_tid] = [
        {"key": "class", "name": "类型",
         "value": [{"n": x, "v": "" if x == "全部" else x}
                   for x in _FILTERS_MAP[_tid]]},
        {"key": "area", "name": "地区", "value": _AREAS},
        {"key": "year", "name": "年份", "value": _YEARS},
    ]


# ===================== 正则 =====================
# 列表卡片: href + title + 备注/人气 + 图片(data-original 或 src)
_RE_CARD = re.compile(
    r'<a\s+href="(/voddetail/\d+\.html)"\s+title="([^"]*)"[^>]*>'
    r'([\s\S]*?)</a>', re.I)
_RE_NOTE = re.compile(r'class="module-item-note">([^<]*)<', re.I)
_RE_DOUBAN = re.compile(r'class="module-item-douban">([^<]*)<', re.I)
_RE_PIC_DATA = re.compile(r'data-original="([^"]+)"', re.I)
_RE_PIC_ANY = re.compile(
    r'<img[^>]*?(?:data-original|data-src|src)="([^"]*)"', re.I | re.S)

_RE_HREF = re.compile(r'href="(/voddetail/\d+\.html)"', re.I)
_RE_IMG = re.compile(
    r'(?:data-original|data-src|src)="([^"]+\.(?:jpg|jpeg|png|webp)[^"]*)"',
    re.I)

# 播放线路标签(按顺序): data-dropdown-value="哔哩哔哩"
_RE_TAB = re.compile(r'data-dropdown-value="([^"]+)"', re.I)
# 播放集数: href="/vodplay/{vid}-{src}-{ep}.html" title="..."<span>..</span>
_RE_PLAY_A = re.compile(
    r'<a[^>]+href="(/vodplay/\d+-(\d+)-\d+\.html)"\s+title="([^"]*)"',
    re.I)
_RE_SPAN = re.compile(r'<span>([^<]*)</span>', re.I)

# 详情页
_RE_TITLE_TAG = re.compile(r'<title>(.*?)</title>', re.S | re.I)
_RE_H1 = re.compile(r'<h1[^>]*>([\s\S]*?)</h1>', re.I)
_RE_PIC_ID = re.compile(
    r'data-original="(https?://[^"]+\.(?:jpg|jpeg|png|webp)[^"]*)"', re.I)
_RE_INTRO = re.compile(
    r'module-info-introduction-content[^"]*"[^>]*>\s*<p>([\s\S]*?)</p>',
    re.I)
_RE_META_DESC = re.compile(
    r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']',
    re.I)
# module-info-item 块: <span class="module-info-item-title">导演：</span>...
_RE_INFO_BLOCK = re.compile(
    r'<span\s+class="module-info-item-title">([^：<]*)：?</span>\s*'
    r'<div class="module-info-item-content">([\s\S]*?)</div>', re.I)

# 播放页 player_aaaa
_RE_PLAYER = re.compile(r'player_aaaa\s*=\s*(\{[\s\S]*?\})\s*[;<]', re.I)

# maccms 验证码页特征
_RE_CAPTCHA = re.compile(r'(系统安全验证|需要输入验证码|ajax/verify_check)')


class Spider(Spider):

    def getName(self):
        return "66大片网"

    def init(self, extend=""):
        try:
            self.extend = json.loads(extend) if extend else {}
        except Exception:
            self.extend = {}

        self.site_url = (self.extend.get("site") or HOST).rstrip("/")
        self.headers = {
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Referer": self.site_url + "/",
            "Upgrade-Insecure-Requests": "1",
        }
        self.default_pic = DEFAULT_PIC
        self._play_cache = {}
        self.log("init: site=%s" % self.site_url)

    def _fetch(self, url, timeout=30, headers=None, referer=None):
        try:
            h = dict(self.headers)
            if referer:
                h["Referer"] = referer
            if headers:
                h.update(headers)
            rsp = self.fetch(url, headers=h, timeout=timeout)
            text = ""
            if hasattr(rsp, "text"):
                text = rsp.text or ""
            elif hasattr(rsp, "content"):
                text = rsp.content.decode("utf-8", "ignore")
            else:
                text = str(rsp)
            if _RE_CAPTCHA.search(text):
                self.log("⚠️ 触发验证码: %s" % url)
                return ""
            return text
        except Exception as e:
            self.log("fetch FAIL %s -> %s" % (url, e))
            return ""

    def _fix_url(self, url):
        if not url:
            return ""
        url = url.strip()
        if url.startswith("//"):
            return "https:" + url
        if url.startswith("http"):
            return url
        if url.startswith("/"):
            return self.site_url + url
        return urllib.parse.urljoin(self.site_url + "/", url)

    def _clean(self, s):
        if not s:
            return ""
        s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
        s = re.sub(r"<[^>]+>", "", s)
        s = (s.replace("&nbsp;", " ").replace("\xa0", " ")
              .replace("&amp;", "&").replace("&quot;", '"')
              .replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">")
              .replace("\t", ""))
        s = re.sub(r"[ \r\f\v]+", " ", s)
        s = re.sub(r"\n{2,}", "\n", s)
        return s.strip()

    # -------- 列表解析 --------
    def _extract_videos(self, html):
        videos = []
        seen = set()
        if not html:
            self.log("  HTML 为空")
            return videos

        matches = _RE_CARD.findall(html)
        self.log("  完整卡片: %d 条" % len(matches))

        if matches:
            for href, title, block in matches:
                if href in seen:
                    continue
                seen.add(href)
                name = self._clean(title)
                pic = ""
                mp = _RE_PIC_DATA.search(block)
                if mp:
                    pic = mp.group(1)
                else:
                    for mi in _RE_PIC_ANY.finditer(block):
                        u = mi.group(1)
                        if u and "load.gif" not in u:
                            pic = u
                            break
                        if u and not pic:
                            pic = u
                remark = ""
                mn = _RE_NOTE.search(block)
                if mn:
                    remark = self._clean(mn.group(1))
                if not remark:
                    md = _RE_DOUBAN.search(block)
                    if md:
                        remark = self._clean(md.group(1))
                videos.append({
                    "vod_id":      href,
                    "vod_name":    name[:100] or href,
                    "vod_pic":     self._fix_url(pic) or self.default_pic,
                    "vod_remarks": remark[:20],
                })
            return videos

        # 兜底: 分开提取
        hrefs = _RE_HREF.findall(html)
        imgs = _RE_IMG.findall(html)
        self.log("  分开: href=%d img=%d" % (len(hrefs), len(imgs)))
        for i, href in enumerate(hrefs):
            if href in seen:
                continue
            seen.add(href)
            pic = imgs[i] if i < len(imgs) else ""
            videos.append({
                "vod_id":      href,
                "vod_name":    href.strip("/").split("/")[-1],
                "vod_pic":     self._fix_url(pic) or self.default_pic,
                "vod_remarks": "",
            })
        return videos

    def _page_count(self, html):
        if not html:
            return 1
        pages = re.findall(r'/page/(\d+)\.html', html)
        if pages:
            try:
                return max(int(p) for p in pages)
            except Exception:
                pass
        return 9999

    # -------- TVBox 接口 --------
    def homeContent(self, filter=False):
        return {"class": CLASSES, "filters": FILTERS}

    def homeVideoContent(self):
        html = self._fetch(self.site_url + "/")
        self.log("home HTML 长度: %d" % len(html))
        return {"list": self._extract_videos(html)}

    def categoryContent(self, tid, pg, filter, extend):
        page = int(pg) if pg else 1
        if isinstance(extend, str):
            try:
                extend = json.loads(extend)
            except Exception:
                extend = {}
        if not extend:
            extend = {}
        for k in list(extend.keys()):
            if extend[k] in ("", None, "全部"):
                del extend[k]

        # maccms 路径式筛选: /vodtype/{tid}/class/{v}/area/{v}/year/{v}
        segs = []
        for key in ("class", "area", "year"):
            if extend.get(key):
                segs.append(key)
                segs.append(urllib.parse.quote(str(extend[key])))
        if page > 1:
            segs.extend(["page", str(page)])
        url = "%s/vodtype/%s%s.html" % (
            self.site_url, tid,
            ("/" + "/".join(segs)) if segs else "")
        self.log("category: %s" % url)
        html = self._fetch(url)
        self.log("  HTML 长度: %d" % len(html))

        videos = self._extract_videos(html)
        pagecount = self._page_count(html)
        self.log("  最终: %d 条, 总页数: %d" % (len(videos), pagecount))

        return {
            "list": videos, "page": page, "pagecount": pagecount,
            "limit": 24, "total": pagecount * 24,
        }

    def searchContent(self, key, quick, pg="1"):
        page = int(pg) if pg else 1
        # maccms 搜索: /vodsearch/{wd}-------------.html (第 - 页参数位)
        dashes = "-------------"[:11] + ("%d" % page) + "---"
        url = "%s/vodsearch/%s%s.html" % (
            self.site_url, urllib.parse.quote(key), dashes)
        self.log("search: %s" % url)
        html = self._fetch(url)
        self.log("  HTML 长度: %d" % len(html))
        videos = self._extract_videos(html)
        return {
            "list": videos, "page": page,
            "pagecount": self._page_count(html) if videos else page,
            "limit": 24, "total": 999 if videos else page * 24,
        }

    def searchContentPage(self, key, quick, pg="1"):
        return self.searchContent(key, quick, pg)

    def detailContent(self, ids):
        if not ids:
            return {"list": []}
        vod_id = str(ids[0])
        if re.fullmatch(r"\d+", vod_id):
            vod_id = "/voddetail/%s.html" % vod_id
        url = vod_id if vod_id.startswith("http") else self._fix_url(vod_id)
        self.log("detail: %s" % url)

        html = self._fetch(url)
        self.log("  HTML 长度: %d" % len(html))
        if not html:
            return {"list": []}

        # 标题
        name = ""
        try:
            m = _RE_H1.search(html)
            if m:
                name = self._clean(m.group(1))
        except Exception:
            pass
        if not name:
            try:
                m = _RE_TITLE_TAG.search(html)
                if m:
                    name = self._clean(m.group(1))
            except Exception:
                pass
        # 去掉 "- 66 大片网_..." 后缀与年份
        name = re.split(r"[-_]\s*66\s*大片网", name)[0]
        name = re.sub(r"(大陆番详情介绍|详情介绍|免费在线观看|高清完整版下载)",
                      "", name).strip()
        name = re.sub(r"\s*[\(（]\d{4}[\)）]\s*$", "", name).strip() or vod_id

        # 封面
        pic = self.default_pic
        try:
            m = _RE_PIC_ID.search(html)
            if m:
                pic = m.group(1)
        except Exception:
            pass

        # 简介
        content = ""
        try:
            m = _RE_INTRO.search(html)
            if m:
                content = self._clean(m.group(1))
        except Exception:
            pass
        if not content:
            try:
                m = _RE_META_DESC.search(html)
                if m:
                    content = self._clean(m.group(1))
            except Exception:
                pass

        if content:
            content = INTRO_PREFIX + "\n" + content
        else:
            content = INTRO_PREFIX

        # 元信息 (导演/主演等)
        director = ""
        actor = ""
        year = ""
        try:
            for k, v in _RE_INFO_BLOCK.findall(html):
                val = self._clean(v).strip("/ ").strip()
                k = self._clean(k)
                if k == "导演" and val:
                    director = re.sub(r"\s*/\s*", ", ", val)
                elif k == "主演" and val:
                    actor = re.sub(r"\s*/\s*", ", ", val)
                elif k in ("年份", "上映") and val:
                    year = val
        except Exception as e:
            self.log("  元信息解析失败: %s" % e)

        # ===== 线路与剧集 =====
        # 线路名按 data-dropdown-value 顺序; 集数按 href 中 src 序号分组
        tabs = [self._clean(t) for t in _RE_TAB.findall(html)]
        tabs = [t for t in tabs if t]
        groups = {}
        try:
            for m in _RE_PLAY_A.finditer(html):
                href, src_idx, title = m.group(1), int(m.group(2)), m.group(3)
                # 标签内的 span 文本更干净
                seg = html[m.end():m.end() + 200]
                ms = _RE_SPAN.search(seg)
                ep_name = self._clean(ms.group(1)) if ms else ""
                if not ep_name:
                    ep_name = self._clean(title)
                if not ep_name:
                    ep_name = "第%d集" % len(groups.get(src_idx, []))
                href = href.replace("&amp;", "&")
                groups.setdefault(src_idx, []).append((ep_name, href))
        except Exception as e:
            self.log("  剧集解析失败: %s" % e)

        self.log("  剧集: %s" % {k: len(v) for k, v in groups.items()})

        if not groups:
            return {"list": []}

        # 线路排序: 直链源(极速/资源类)在前, 需嗅探的外链(哔哩哔哩等)靠后
        def _line_key(src_idx):
            name = tabs[src_idx - 1] if src_idx - 1 < len(tabs) else ""
            if any(w in name for w in ("哔哩", "bilibili", "B站")):
                return 2
            if any(w in name for w in ("极速", "量子", "暴风", "非凡",
                                       "资源", "天空", "无尽", "红牛")):
                return 0
            return 1

        play_from = []
        play_url = []
        for src_idx in sorted(groups.keys(),
                              key=lambda x: (_line_key(x), x)):
            eps = groups[src_idx]
            if src_idx - 1 < len(tabs):
                alias = tabs[src_idx - 1]
            else:
                alias = "线路%d" % src_idx
            play_from.append(alias)
            play_url.append("#".join(
                "%s$%s" % (n, self._fix_url(h)) for n, h in eps))

        remarks = []
        if year:
            remarks.append(year)
        remarks.append("%d条线路" % len(groups))

        return {"list": [{
            "vod_id": vod_id,
            "vod_name": name,
            "vod_pic": pic,
            "vod_content": content,
            "vod_actor": actor,
            "vod_director": director,
            "vod_year": year,
            "vod_remarks": " · ".join(remarks),
            "vod_play_from": "$$$".join(play_from),
            "vod_play_url":  "$$$".join(play_url),
        }]}

    # -------- 播放 --------
    def playerContent(self, flag, id, vipFlags):
        play_page = id if id.startswith("http") else self._fix_url(id)
        self.log("player: %s flag=%s" % (play_page, flag))

        now = int(time.time())
        if play_page in self._play_cache:
            ts, res = self._play_cache[play_page]
            if now - ts < 600:
                return res

        real_url = ""
        html = self._fetch(play_page, referer=self.site_url + "/")
        if html:
            real_url = self._extract_play_url(html)
        self.log("  real_url: %s" % (real_url[:200] if real_url else "EMPTY"))

        if real_url:
            low = real_url.lower()
            # 外链嗅探 (哔哩哔哩等非直链)
            if ".m3u8" not in low and ".mp4" not in low \
                    and ".flv" not in low and not real_url.endswith(".mp4"):
                res = {
                    "parse": 1, "playUrl": "", "url": real_url,
                    "header": {"User-Agent": UA},
                }
                self._play_cache[play_page] = (now, res)
                return res

            # 直链 m3u8/mp4
            res = {
                "parse": 0,
                "playUrl": "",
                "url": real_url,
                "header": {
                    "User-Agent": UA,
                    "Referer": self.site_url + "/",
                },
            }
            self._play_cache[play_page] = (now, res)
            return res

        # 兜底: 嗅探播放页
        res = {
            "parse": 1, "playUrl": "", "url": play_page,
            "header": {"User-Agent": UA, "Referer": self.site_url + "/"},
        }
        self._play_cache[play_page] = (now, res)
        return res

    def _extract_play_url(self, html):
        """解析 player_aaaa: encrypt=2 时 url 为 base64(URL编码)"""
        if not html:
            return ""
        m = _RE_PLAYER.search(html)
        raw = m.group(1) if m else ""

        url = ""
        if raw:
            try:
                cfg = json.loads(raw.replace("\\/", "/"))
                url = cfg.get("url", "")
                encrypt = int(cfg.get("encrypt", 0) or 0)
                if encrypt == 2 and url:
                    url = urllib.parse.unquote(
                        base64.b64decode(url + "=" * (-len(url) % 4))
                        .decode("utf-8", "ignore"))
                elif encrypt == 1 and url:
                    url = urllib.parse.unquote(url)
            except Exception as e:
                self.log("  player_aaaa 解析失败: %s" % e)
                url = ""

        if not url:
            # 兜底: 找裸 m3u8 / base64 url 字段
            m2 = re.search(r'"url"\s*:\s*"(J[A-Za-z0-9+/=]+)"', html)
            if m2:
                try:
                    url = urllib.parse.unquote(
                        base64.b64decode(m2.group(1) + "===").decode(
                            "utf-8", "ignore"))
                except Exception:
                    url = ""
            if not url:
                m3 = re.search(r'"url"\s*:\s*"([^"]+)"', html)
                if m3:
                    url = m3.group(1).replace("\\/", "/")

        return url.replace("&amp;", "&")

    def localProxy(self, param):
        try:
            url = ""
            if isinstance(param, dict):
                url = param.get("url", "")
            else:
                for pair in str(param).split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        if k == "url":
                            url = v
            if not url:
                return [200, "image/jpeg", b"", ""]
            url = urllib.parse.unquote(url) if "%" in url else url
            url = self._fix_url(url)
            rsp = self.fetch(url, headers={
                "User-Agent": UA,
                "Referer": self.site_url + "/",
            }, timeout=15)
            content = rsp.content
            ctype = rsp.headers.get("Content-Type", "image/jpeg")
            if not ctype.startswith("image/"):
                ctype = "image/jpeg"
            return [200, ctype, content, ""]
        except Exception:
            return [200, "image/jpeg", b"", ""]

    def isVideoFormat(self, url):
        return ".m3u8" in url or ".mp4" in url or url.startswith("http")

    def manualVideoCheck(self):
        return False

    def destroy(self):
        pass

    def close(self):
        self.destroy()
