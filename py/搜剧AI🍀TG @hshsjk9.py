# coding=utf-8
"""
搜剧AI souju.ai | TVBox Python 爬虫
关键:
  - 请求签名: HMAC-SHA256(secret, "GET\n{path}{query}\n{timestamp}\n{nonce}")
    headers: x-ai-movie-timestamp / x-ai-movie-nonce / x-ai-movie-signature
  - 分类/搜索: GET /v1/browse/catalog (kind/genre/area/year/sort/q/page/limit)
  - 详情+剧集: GET /v1/catalog/{variant_id} (episodes 按 offset 分页)
  - 播放解析: GET /v1/playback/resolve/{episode_token}?view=compact
    -> line_options[] 直接给出 m3u8 直链 (parse=0)
"""
import re
import sys
import json
import time
import hmac
import hashlib
import secrets
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
                print("[souju]", *a)
            except Exception:
                pass

    Spider = _BaseSpider


HOST = "https://souju.ai"

# 站点请求签名密钥 (来自前端 JS, 与官网完全一致)
SIGN_SECRET = ("f39d73aa7a6426203cdee1ef17b31d3b7ea8c23f4c59c62a3a"
               "8aa0f39ee5e79d")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

DEFAULT_PIC = "https://souju.ai/assets/app-icon-512.png"

INTRO_PREFIX = "🍊小橙子为您介绍剧情👉请不要相信视频中的广告，以免上当受骗！"

CLASSES = [
    {"type_id": "movie",       "type_name": "电影"},
    {"type_id": "series",      "type_name": "电视剧"},
    {"type_id": "variety",     "type_name": "综艺"},
    {"type_id": "anime",       "type_name": "动漫"},
    {"type_id": "short_drama", "type_name": "短剧"},
]

# 与官网 /v1/runtime/bootstrap 下发的筛选项保持一致
_GENRE_MAP = {
    "movie": ["喜剧", "爱情", "动作", "犯罪", "科幻", "奇幻", "冒险", "灾难",
              "恐怖", "惊悚", "剧情", "战争", "歌舞", "经典", "悬疑", "动画",
              "同性", "网络电影"],
    "series": ["偶像", "爱情", "言情", "古装", "历史", "玄幻", "谍战", "历险",
               "都市", "科幻", "军旅", "喜剧", "武侠", "江湖", "罪案", "青春",
               "家庭", "战争", "悬疑", "穿越", "宫廷", "神话", "商战", "警匪",
               "动作", "惊悚", "剧情", "同性", "奇幻"],
    "anime": ["热血", "格斗", "机战", "少女", "竞技", "科幻", "魔幻", "爆笑",
              "推理", "冒险", "恋爱", "校园", "治愈", "泡面", "穿越", "灵异",
              "耽美", "剧场版", "其它"],
    "variety": ["真人秀", "选秀", "网综", "脱口秀", "搞笑", "竞技", "情感",
                "访谈", "演唱会", "晚会", "其它"],
    "short_drama": ["真人剧", "comic", "偶像", "爱情", "言情", "古装", "历史",
                    "玄幻", "谍战", "都市", "历险", "科幻", "军旅", "喜剧",
                    "武侠", "江湖", "罪案", "青春", "家庭", "战争", "悬疑",
                    "穿越", "宫廷", "神话", "商战", "警匪", "动作", "惊悚",
                    "剧情", "同性", "奇幻", "女性", "系统", "逆袭", "无敌",
                    "乡村", "古风", "赘婿", "萌宝", "种田"],
}

_AREAS = [
    {"n": "全部", "v": ""},
    {"n": "大陆", "v": "大陆"}, {"n": "香港", "v": "香港"},
    {"n": "台湾", "v": "台湾"}, {"n": "日本", "v": "日本"},
    {"n": "韩国", "v": "韩国"}, {"n": "欧美", "v": "欧美"},
    {"n": "英国", "v": "英国"}, {"n": "泰国", "v": "泰国"},
    {"n": "其它", "v": "其它"},
]

_YEARS = [{"n": "全部", "v": ""}] + \
         [{"n": str(y), "v": str(y)} for y in range(2026, 1999, -1)]

_SORTS = [
    {"n": "最近更新", "v": "updated_desc"},
    {"n": "热度最高", "v": "heat_desc"},
]

FILTERS = {}
for c in CLASSES:
    tid = c["type_id"]
    FILTERS[tid] = [
        {"key": "genre", "name": "分类",
         "value": [{"n": x, "v": x} for x in _GENRE_MAP.get(tid, [])]},
        {"key": "area", "name": "地区", "value": _AREAS},
        {"key": "year", "name": "年份", "value": _YEARS},
        {"key": "sort", "name": "排序", "value": _SORTS},
    ]

PAGE_LIMIT = 24


class Spider(Spider):

    def getName(self):
        return "搜剧AI"

    def init(self, extend=""):
        try:
            self.extend = json.loads(extend) if extend else {}
        except Exception:
            self.extend = {}

        self.site_url = (self.extend.get("site") or HOST).rstrip("/")
        self.headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": self.site_url + "/",
            "Origin": self.site_url,
        }
        self.default_pic = DEFAULT_PIC
        self._detail_cache = {}
        self._play_cache = {}
        self.log("init: site=%s" % self.site_url)

    # ===================== 签名与请求 =====================
    def _signed_fetch(self, path, params=None, timeout=20):
        """对 /v1/ 接口按官网规则进行 HMAC-SHA256 请求签名后 GET。"""
        try:
            query = ""
            if params:
                query = urllib.parse.urlencode(params)
            url = self.site_url + path + (("?" + query) if query else "")

            ts = str(int(time.time() * 1000))
            nonce = secrets.token_hex(16)
            msg = "GET\n%s%s\n%s\n%s" % (path, ("?" + query) if query else "",
                                         ts, nonce)
            sig = hmac.new(SIGN_SECRET.encode(), msg.encode(),
                           hashlib.sha256).hexdigest()

            h = dict(self.headers)
            h["x-ai-movie-timestamp"] = ts
            h["x-ai-movie-nonce"] = nonce
            h["x-ai-movie-signature"] = sig

            rsp = self.fetch(url, headers=h, timeout=timeout)
            text = ""
            if hasattr(rsp, "text"):
                text = rsp.text or ""
            elif hasattr(rsp, "content"):
                text = rsp.content.decode("utf-8", "ignore")

            try:
                return json.loads(text)
            except Exception:
                self.log("signed_fetch 非JSON: %s len=%d" % (path, len(text)))
                return {}
        except Exception as e:
            self.log("signed_fetch FAIL %s -> %s" % (path, e))
            return {}

    def _browse(self, params):
        base = {"page": 1, "limit": PAGE_LIMIT}
        base.update({k: v for k, v in params.items() if v})
        return self._signed_fetch("/v1/browse/catalog", base)

    def _cards_to_videos(self, data):
        videos = []
        for card in (data.get("cards") or []):
            try:
                videos.append({
                    "vod_id":      card.get("id") or "",
                    "vod_name":    (card.get("title") or "")[:100],
                    "vod_pic":     card.get("poster_url") or self.default_pic,
                    "vod_remarks": (card.get("remarks") or "")[:20],
                })
            except Exception:
                continue
        return [v for v in videos if v["vod_id"]]

    # ===================== TVBox 标准接口 =====================
    def homeContent(self, filter=False):
        return {"class": CLASSES, "filters": FILTERS}

    def homeVideoContent(self):
        data = self._signed_fetch("/v1/feed/home")
        videos = []
        for section in (data.get("sections") or []):
            videos += self._cards_to_videos(section)
        seen, uniq = set(), []
        for v in videos:
            if v["vod_id"] not in seen:
                seen.add(v["vod_id"])
                uniq.append(v)
        return {"list": uniq}

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

        params = {"kind": tid, "page": page, "limit": PAGE_LIMIT}
        if extend.get("genre"):
            params["genre"] = extend["genre"]
        if extend.get("area"):
            params["area"] = extend["area"]
        if extend.get("year"):
            params["year"] = extend["year"]
        params["sort"] = extend.get("sort") or "updated_desc"

        data = self._browse(params)
        videos = self._cards_to_videos(data)

        pagecount = 9999
        pagination = data.get("pagination") or {}
        total = pagination.get("total")
        try:
            if total:
                pagecount = min(9999, (int(total) + PAGE_LIMIT - 1)
                                // PAGE_LIMIT)
            elif pagination.get("has_more") is False:
                pagecount = page
        except Exception:
            pass

        return {
            "list": videos, "page": page, "pagecount": pagecount,
            "limit": PAGE_LIMIT, "total": pagecount * PAGE_LIMIT,
        }

    def searchContent(self, key, quick, pg="1"):
        page = int(pg) if pg else 1
        data = self._browse({"q": key, "page": page,
                             "limit": PAGE_LIMIT, "intent": "catalog_search"})
        videos = self._cards_to_videos(data)

        pagecount = 9999
        pagination = data.get("pagination") or {}
        try:
            total = pagination.get("total")
            if total:
                pagecount = min(9999, (int(total) + PAGE_LIMIT - 1)
                                // PAGE_LIMIT)
            elif pagination.get("has_more") is False:
                pagecount = page
        except Exception:
            pass

        return {
            "list": videos, "page": page, "pagecount": pagecount,
            "limit": PAGE_LIMIT, "total": pagecount * PAGE_LIMIT,
        }

    def searchContentPage(self, key, quick, pg="1"):
        return self.searchContent(key, quick, pg)

    def detailContent(self, ids):
        if not ids:
            return {"list": []}
        vod_id = str(ids[0])
        self.log("detail: %s" % vod_id[:80])

        data = self._signed_fetch("/v1/catalog/" + urllib.parse.quote(vod_id))
        if not data or data.get("ERR"):
            return {"list": []}

        name = data.get("title") or vod_id
        pic = data.get("poster_url") or data.get("backdrop_url") \
            or self.default_pic
        year = data.get("year") or ""
        area = data.get("area") or ""
        genres = " ".join(data.get("genres") or [])
        remarks = data.get("remarks") or ""

        content = (data.get("description") or "").strip()
        if content:
            content = INTRO_PREFIX + "\n" + content
        else:
            content = INTRO_PREFIX

        actor = ", ".join(data.get("actors") or [])
        director = ", ".join(data.get("directors") or [])

        # ===== 剧集 (按 offset 分页拉全) =====
        episodes = list(data.get("episodes") or [])
        try:
            ep_pg = data.get("episode_pagination") or {}
            offset = ep_pg.get("offset", 0) + (ep_pg.get("limit") or 0)
            guard = 0
            while ep_pg.get("has_more") and guard < 50:
                more = self._signed_fetch(
                    "/v1/catalog/%s/episodes" % urllib.parse.quote(vod_id),
                    {"limit": ep_pg.get("limit") or 48, "offset": offset})
                batch = more.get("episodes") or []
                if not batch:
                    break
                episodes += batch
                ep_pg = more.get("episode_pagination") or {}
                offset += (ep_pg.get("limit") or 48)
                guard += 1
        except Exception as e:
            self.log("  剧集分页拉取失败: %s" % e)

        # 去重 (主 track 优先)
        seen_tokens, seen_ids = set(), set()
        eps = []
        for ep in episodes:
            tok = ep.get("token") or ""
            eid = ep.get("id") or ""
            if tok and tok in seen_tokens:
                continue
            if eid and eid in seen_ids:
                continue
            if tok:
                seen_tokens.add(tok)
            if eid:
                seen_ids.add(eid)
            eps.append(ep)

        if not eps:
            return {"list": []}

        ep_names = []
        for ep in eps:
            n = (ep.get("display_name") or ep.get("title") or "").strip()
            if not n:
                n = "第%d集" % (len(ep_names) + 1)
            tok = ep.get("token") or ep.get("id")
            ep_names.append("%s$%s" % (n.replace("$", " "), tok))

        play_from = ["搜剧AI"]
        play_url = ["#".join(ep_names)]

        vod_remarks = remarks or ("%d集" % len(eps))
        if year:
            vod_remarks = "%s · %s" % (year, vod_remarks)

        self._detail_cache[vod_id] = {"name": name, "pic": pic}

        return {"list": [{
            "vod_id": vod_id,
            "vod_name": name,
            "vod_pic": pic,
            "type_name": genres,
            "vod_year": str(year),
            "vod_area": area,
            "vod_actor": actor,
            "vod_director": director,
            "vod_remarks": vod_remarks,
            "vod_content": content,
            "vod_play_from": "$$$".join(play_from),
            "vod_play_url":  "$$$".join(play_url),
        }]}

    # -------- 播放 --------
    def playerContent(self, flag, id, vipFlags):
        ep_token = id if id.startswith("http") else id
        self.log("player: %s" % ep_token[:80])

        now = int(time.time())
        if ep_token in self._play_cache:
            ts, res = self._play_cache[ep_token]
            if now - ts < 600:
                return res

        data = self._signed_fetch(
            "/v1/playback/resolve/" + urllib.parse.quote(ep_token),
            {"view": "compact"})

        url = ""
        lines = data.get("line_options") or []
        # 优先已选中的线路, 否则取第一个有直链的
        lines = sorted(lines, key=lambda x: (0 if x.get("selected") else 1,
                                             -x.get("preference_weight", 0)))
        for ln in lines:
            u = (ln.get("url") or "").strip()
            if u.startswith("http"):
                url = u
                if ln.get("provider_name") or ln.get("label"):
                    self.log("  线路: %s" % (ln.get("label")
                                             or ln.get("provider_name")))
                break

        if not url:
            cur = data.get("current_episode") or {}
            for u in (cur.get("urls") or {}).values():
                if isinstance(u, str) and u.startswith("http"):
                    url = u
                    break

        if url and ".m3u8" in url.lower():
            res = {
                "parse": 0,
                "playUrl": "",
                "url": url,
                "header": {
                    "User-Agent": UA,
                    "Referer": self.site_url + "/",
                },
            }
            self._play_cache[ep_token] = (now, res)
            self.log("  => 直链 m3u8: %s" % url[:160])
            return res

        # 兜底: 交给 TVBox 嗅探详情页
        res = {"parse": 1, "playUrl": "", "url": self.site_url,
               "header": {"User-Agent": UA, "Referer": self.site_url + "/"}}
        self._play_cache[ep_token] = (now, res)
        return res

    def localProxy(self, param):
        return [200, "image/jpeg", b"", ""]

    def isVideoFormat(self, url):
        return ".m3u8" in url or ".mp4" in url or url.startswith("http")

    def manualVideoCheck(self):
        return False

    def destroy(self):
        pass

    def close(self):
        self.destroy()
