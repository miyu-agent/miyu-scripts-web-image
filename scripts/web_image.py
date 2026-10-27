#!/usr/bin/env python3
# Display name: Web image search
# 显示名称：网络搜图
# Description: Search the web for images, save them into the user's Pictures (the script cache, newest 10 searches, where Pictures is not given) and attach the first few for you to see.
# 描述：上网搜图：存进用户的图片目录（没有的会话存进脚本缓存，只留最近 10 次），前几张直接给 AI 看，要给人看用 show。
# Timeout: 90
# Clicall: no
# Parameters:
# {"type": "object", "properties": {
#   "query": {"type": "string", "description": "What to search for. Write it the way people would caption the picture; Chinese works."},
#   "count": {"type": "integer", "description": "How many images to save, 1-20. Match what the user asked for. Default 4. At most 4 are attached for you to see; the rest are only saved."},
#   "safe_search": {"type": "boolean", "description": "Filter adult results. Default true. Turning it off also adds Baidu and 360 for Chinese queries."}
# }, "required": ["query"]}
import concurrent.futures
import hashlib
import html
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36")
MAX_COUNT = 20
MAX_SEARCH_BYTES = 8 << 20
MAX_IMAGE_BYTES = 20 << 20
ATTACH_LIMIT = 4
ATTACH_BYTES = 5 << 20
ATTACH_SIDE = 8000
MIN_SIDE = 100
SEARCH_TIMEOUT = 15
DOWNLOAD_TIMEOUT = 20
COOLDOWN_BLOCKED = 600
COOLDOWN_FLAKY = 120

# Proxies in fake-IP mode (Clash and friends) answer every name from this range.
FAKE_IP = ipaddress.ip_network("198.18.0.0/15")

PROVIDER_NAMES = {"duckduckgo": "DuckDuckGo", "bing": "必应", "baidu": "百度", "so360": "360"}


def fail(message):
    print(f"错误：{message}")
    sys.exit(1)


def is_cjk(ch):
    return 0x3400 <= ord(ch) <= 0x4DBF or 0x4E00 <= ord(ch) <= 0x9FFF or 0xF900 <= ord(ch) <= 0xFAFF


# --------------------------------------------------------------------------
# Network access refuses anything that is not a public address, on every hop
# --------------------------------------------------------------------------

def public_url(url):
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return False
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global and address not in FAKE_IP:
            return False
    return bool(infos)


class GuardedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not public_url(newurl):
            raise urllib.error.URLError(f"redirect to a non-public address: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(GuardedRedirect)


def fetch(url, referer="", limit=MAX_SEARCH_BYTES, timeout=SEARCH_TIMEOUT, accept=None):
    """GET a public URL; return (bytes, final_url, content_type)."""
    if not public_url(url):
        raise urllib.error.URLError(f"not a public address: {url}")
    headers = {
        "User-Agent": UA,
        "Accept": accept or "text/html,application/json,image/avif,image/webp,image/*,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    if referer:
        headers["Referer"] = referer
    request = urllib.request.Request(url, headers=headers)
    with OPENER.open(request, timeout=timeout) as response:
        length = response.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > limit:
            raise ValueError("response too large")
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("response too large")
        return data, response.geturl(), response.headers.get_content_type()


def looks_like_challenge(text):
    lower = text.lower()
    return any(m in lower for m in ("anomaly-modal", "captcha", "challenge-form", "robot check"))


# --------------------------------------------------------------------------
# providers
# --------------------------------------------------------------------------

def candidate(title, page, image, thumb, provider, width=0, height=0):
    image = html.unescape((image or "").strip())
    if not image.startswith(("http://", "https://")):
        return None
    try:
        width, height = int(width or 0), int(height or 0)
    except (TypeError, ValueError):
        width = height = 0
    return {
        "title": " ".join(html.unescape(title or "").split())[:180],
        "page": html.unescape((page or "").strip()),
        "image": image,
        "thumb": html.unescape((thumb or "").strip()),
        "provider": provider,
        "width": width,
        "height": height,
    }


def search_duckduckgo(query, limit, safe):
    page = "https://duckduckgo.com/?" + urllib.parse.urlencode({"q": query, "iax": "images", "ia": "images"})
    text = fetch(page)[0].decode("utf-8", "replace")
    if looks_like_challenge(text):
        raise RuntimeError("challenge page")
    match = re.search(r"""vqd\s*[=:]\s*["']?([\d-]+)""", text) or re.search(r'"vqd":"([\d-]+)"', text)
    if not match:
        raise RuntimeError("no vqd token")
    api = "https://duckduckgo.com/i.js?" + urllib.parse.urlencode({
        "q": query, "o": "json", "p": "1" if safe else "-1", "s": "0", "u": "bing", "f": ",,,",
        "l": "cn-zh" if any(map(is_cjk, query)) else "wt-wt", "vqd": match.group(1),
    })
    body = fetch(api, referer=page)[0].decode("utf-8", "replace")
    if looks_like_challenge(body):
        raise RuntimeError("challenge page")
    out = []
    for item in json.loads(body).get("results", [])[:limit]:
        c = candidate(item.get("title"), item.get("url"), item.get("image"), item.get("thumbnail"),
                      "duckduckgo", item.get("width"), item.get("height"))
        if c:
            out.append(c)
    return out


def search_bing(query, limit, safe):
    params = {"q": query, "first": "1", "mkt": "zh-CN"}
    if safe:
        params["safeSearch"] = "Strict"
    text = fetch("https://cn.bing.com/images/search?" + urllib.parse.urlencode(params))[0].decode("utf-8", "replace")
    out = []
    for raw in re.findall(r'class="iusc"[^>]*?\sm="([^"]+)"', text):
        try:
            data = json.loads(html.unescape(raw))
        except ValueError:
            continue
        c = candidate(data.get("t") or data.get("desc"), data.get("purl"), data.get("murl"), data.get("turl"),
                      "bing", data.get("w") or data.get("expw"), data.get("h") or data.get("exph"))
        if c:
            out.append(c)
        if len(out) >= limit:
            break
    return out


def search_baidu(query, limit, safe):
    params = {
        "tn": "resultjson_com", "ipn": "rj", "ct": "201326592", "fp": "result", "word": query,
        "queryWord": query, "cl": "2", "lm": "-1", "ie": "utf-8", "oe": "utf-8", "st": "-1",
        "face": "0", "istype": "2", "nc": "1", "pn": "0", "rn": str(min(limit, 60)),
    }
    body = fetch("https://image.baidu.com/search/acjson?" + urllib.parse.urlencode(params),
                 referer="https://image.baidu.com/")[0].decode("utf-8", "replace")
    data = json.loads(body)
    if "antiFlag" in data:
        raise RuntimeError("anti-bot response")
    out = []
    for item in data.get("data", [])[:limit]:
        if not isinstance(item, dict):
            continue
        rep = (item.get("replaceUrl") or [{}])[0] or {}
        c = candidate(item.get("fromPageTitleEnc"), rep.get("FromURL") or rep.get("FromUrl") or item.get("fromJumpUrl"),
                      rep.get("ObjURL") or rep.get("ObjUrl") or item.get("middleURL"), item.get("thumbURL"),
                      "baidu", item.get("width"), item.get("height"))
        if c:
            out.append(c)
    return out


def search_so360(query, limit, safe):
    params = {"q": query, "src": "srp", "sn": "0", "pn": str(min(limit, 60))}
    body = fetch("https://image.so.com/j?" + urllib.parse.urlencode(params),
                 referer="https://image.so.com/")[0].decode("utf-8", "replace")
    out = []
    for item in json.loads(body).get("list", [])[:limit]:
        c = candidate(item.get("title"), item.get("link"), item.get("img"), item.get("thumb"),
                      "so360", item.get("width"), item.get("height"))
        if c:
            out.append(c)
    return out


SEARCHERS = {"duckduckgo": search_duckduckgo, "bing": search_bing, "baidu": search_baidu, "so360": search_so360}


def providers_for(query, safe):
    names = ["duckduckgo", "bing"]
    if not safe and any(map(is_cjk, query)):
        names += ["baidu", "so360"]  # neither has a safe-search switch
    return names


# --------------------------------------------------------------------------
# provider cooldowns, kept in the cache directory between calls
# --------------------------------------------------------------------------

def cooldown_path():
    base = os.environ.get("MIYU_SCRIPT_CACHE_DIR")
    return os.path.join(base, "cooldowns.json") if base else None


def load_cooldowns():
    path = cooldown_path()
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    now = time.time()
    return {k: v for k, v in data.items() if isinstance(v, (int, float)) and v > now}


KEEP_SEARCHES = 10


def prune(root, keep):
    """Keep only the newest `keep` search folders in the cache."""
    try:
        entries = [e for e in os.scandir(root) if e.is_dir(follow_symlinks=False)]
    except OSError:
        return
    entries.sort(key=lambda e: e.stat(follow_symlinks=False).st_mtime, reverse=True)
    for entry in entries[keep:]:
        shutil.rmtree(entry.path, ignore_errors=True)


def save_cooldowns(data):
    path = cooldown_path()
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except OSError:
        pass


def cooldown_for(error):
    lower = error.lower()
    if any(k in lower for k in ("403", "429", "forbid", "anti-bot", "captcha", "challenge")):
        return COOLDOWN_BLOCKED
    if any(k in lower for k in ("timed out", "timeout", "connection", "name or service", "http error 5")):
        return COOLDOWN_FLAKY
    return 0


# --------------------------------------------------------------------------
# ranking
# --------------------------------------------------------------------------

GENERIC = {"图片", "照片", "高清", "壁纸", "photo", "image", "images", "picture", "wallpaper", "hd", "4k"}
ACCESSORY = ("手机壳", "保护壳", "保护套", "phone case", "模板", "素材", "贴膜")
NOISY = ("thumb", "thumbnail", "sprite", "placeholder", "banner", "advert", "favicon")


def compact(text):
    return "".join(ch.lower() for ch in text if ch.isalnum())


def query_terms(query):
    terms = {t.lower() for t in re.split(r"[\s\W_]+", query) if len(t) >= 2 and t.lower() not in GENERIC}
    for chunk in re.findall(r"[㐀-䶿一-鿿豈-﫿]{4,}", query):
        terms.update(chunk[i:i + 2] for i in range(len(chunk) - 1))
    return terms


def score(query, c, rank):
    title = c["title"].lower()
    meta = f"{title} {c['page']} {c['image']}".lower()
    terms = query_terms(query)
    denom = max(len(terms), 1)
    in_title = sum(1 for t in terms if t in title)
    in_meta = sum(1 for t in terms if t not in title and t in meta)
    s = in_title / denom * 48 + in_meta / denom * 20
    cq = compact(query)
    if len(cq) >= 4 and cq in compact(c["title"]):
        s += 20
    for number in re.findall(r"\d+", query):
        if number not in re.findall(r"\d+", meta):
            s -= 45
    if any(t in meta for t in ACCESSORY) and not any(t in query for t in ACCESSORY):
        s -= 55
    s += 28 / (1 + max(rank - 1, 0) * 0.22)
    short = min(c["width"], c["height"])
    s += 16 if short >= 900 else 13 if short >= 600 else 9 if short >= 300 else 2 if short >= 100 else -4
    if c["width"] * c["height"] >= 1_000_000:
        s += 4
    if any(t in meta for t in NOISY):
        s -= 8
    if "avatar" in meta and "头像" not in query and "avatar" not in query.lower():
        s -= 8
    return s


# --------------------------------------------------------------------------
# image bytes: type and size from the header only
# --------------------------------------------------------------------------

def sniff(data):
    """Return (mime, width, height) for PNG/JPEG/GIF/WebP, or None."""
    if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        w, h = struct.unpack(">II", data[16:24])
        return "image/png", w, h
    if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        w, h = struct.unpack("<HH", data[6:10])
        return "image/gif", w, h
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP" and len(data) >= 30:
        chunk = data[12:16]
        if chunk == b"VP8 ":
            w, h = struct.unpack("<HH", data[26:30])
            return "image/webp", w & 0x3FFF, h & 0x3FFF
        if chunk == b"VP8L":
            b = data[21:25]
            w = 1 + (((b[1] & 0x3F) << 8) | b[0])
            h = 1 + (((b[3] & 0x0F) << 10) | (b[2] << 2) | ((b[1] & 0xC0) >> 6))
            return "image/webp", w, h
        if chunk == b"VP8X":
            w = 1 + int.from_bytes(data[24:27], "little")
            h = 1 + int.from_bytes(data[27:30], "little")
            return "image/webp", w, h
        return None
    if data[:2] == b"\xff\xd8":
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            length = struct.unpack(">H", data[i + 2:i + 4])[0]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                h, w = struct.unpack(">HH", data[i + 5:i + 9])
                return "image/jpeg", w, h
            i += 2 + length
        return None
    return None


EXT = {"image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp"}


def download(c):
    """Try the full image, then the thumbnail. Return (bytes, mime, w, h, used_thumb) or None."""
    urls = [(c["image"], False)]
    if c["thumb"] and c["thumb"] != c["image"]:
        urls.append((c["thumb"], True))
    for url, used_thumb in urls:
        try:
            data = fetch(url, referer=c["page"], limit=MAX_IMAGE_BYTES, timeout=DOWNLOAD_TIMEOUT,
                         accept="image/avif,image/webp,image/png,image/jpeg,image/*;q=0.8")[0]
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
            continue
        info = sniff(data)
        if not info:
            continue
        mime, w, h = info
        if min(w, h) < MIN_SIDE and not used_thumb:
            continue
        return data, mime, w, h, used_thumb
    return None


# --------------------------------------------------------------------------

def slug(query):
    kept = "".join(ch if ch.isalnum() else "-" for ch in query.strip())
    kept = re.sub(r"-+", "-", kept).strip("-")
    return kept[:24] or "images"


def human(size):
    return f"{size / 1024:.0f} KiB" if size < 1 << 20 else f"{size / (1 << 20):.1f} MiB"


def main():
    try:
        args = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        fail(f"参数不是 JSON：{exc}")
    query = str(args.get("query") or "").strip()
    if not query:
        fail("query 是空的：要搜什么图")
    count = args.get("count", 4)
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= MAX_COUNT:
        fail(f"count 要是 1 到 {MAX_COUNT} 的整数")
    safe = args.get("safe_search", True) is not False

    cooldowns = load_cooldowns()
    names = providers_for(query, safe)
    ready = [n for n in names if n not in cooldowns] or [min(names, key=lambda n: cooldowns[n])]
    per_provider = max(count * 3, 12)
    candidates, failures = [], {}
    with concurrent.futures.ThreadPoolExecutor(len(ready)) as pool:
        jobs = {pool.submit(SEARCHERS[n], query, per_provider, safe): n for n in ready}
        for job in concurrent.futures.as_completed(jobs):
            name = jobs[job]
            try:
                found = job.result()
            except Exception as exc:  # each engine fails in its own way
                message = str(exc)[:120] or type(exc).__name__
                failures[name] = message
                wait = cooldown_for(message)
                if wait:
                    cooldowns[name] = time.time() + wait
                continue
            cooldowns.pop(name, None)
            if not found:
                failures[name] = "no results"
            candidates += [(c, rank) for rank, c in enumerate(found, 1)]
    save_cooldowns(cooldowns)

    seen, ranked = set(), []
    for c, rank in sorted(candidates, key=lambda cr: -score(query, cr[0], cr[1])):
        key = c["image"].split("?", 1)[0].lower()
        if key in seen:
            continue
        seen.add(key)
        ranked.append(c)
    if not ranked:
        detail = "；".join(f"{PROVIDER_NAMES[n]}：{m}" for n, m in failures.items()) or "都没有结果"
        fail(f"没搜到「{query}」的图（{detail}）。换个说法，或者过几分钟再试")

    # Download a few extra so that dead links still leave `count` images.
    pool_size = min(len(ranked), count * 2 + 2)
    results = []
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        downloads = list(pool.map(download, ranked[:pool_size]))
    hashes = set()
    for c, got in zip(ranked[:pool_size], downloads):
        if not got:
            continue
        digest = hashlib.sha256(got[0]).hexdigest()
        if digest in hashes:
            continue
        hashes.add(digest)
        results.append((c, got))
        if len(results) >= count:
            break
    if not results:
        fail(f"「{query}」搜到 {len(ranked)} 条结果，但图都下不下来。过一会儿再试，或者换个说法")

    # 本机会话给用户的图片目录，存了就是人的；群里这类会话没有，退回缓存、只留最近几次
    pictures = os.environ.get("MIYU_PICTURES_DIR")
    base = pictures or os.environ.get("MIYU_SCRIPT_CACHE_DIR")
    if not base:
        fail("没有图片目录也没有脚本缓存目录（MIYU_PICTURES_DIR、MIYU_SCRIPT_CACHE_DIR），要在 Miyu 里调")
    root = os.path.join(base, "网络搜图" if pictures else "images")
    folder = os.path.join(root, f"{slug(query)}-{time.strftime('%Y%m%d-%H%M%S')}")
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as exc:
        fail(f"建不了 {folder}：{exc}")
    if not pictures:
        prune(root, keep=KEEP_SEARCHES)
    attach_dir = os.environ.get("MIYU_SCRIPT_IMAGES_DIR")
    attached = []
    lines = []
    for index, (c, (data, mime, w, h, used_thumb)) in enumerate(results, 1):
        path = os.path.join(folder, f"{index:02d}.{EXT[mime]}")
        with open(path, "wb") as fh:
            fh.write(data)
        if (attach_dir and len(attached) < ATTACH_LIMIT and len(data) <= ATTACH_BYTES
                and max(w, h) <= ATTACH_SIDE):
            shutil.copy(path, os.path.join(attach_dir, f"{index:02d}.{EXT[mime]}"))
            attached.append(index)
        note = "，缩略图" if used_thumb else ""
        title = c["title"] or "（无标题）"
        lines.append(f"{index}. `{path}` — {w}×{h} {EXT[mime].upper()} {human(len(data))}{note} — {title}\n"
                     f"   来源页：{c['page'] or '无'}\n   原图：{c['image']}")

    used = [PROVIDER_NAMES[n] for n in ready if n not in failures]
    head = f"「{query}」存了 {len(results)} 张，在 `{folder}/`（来源：{'、'.join(used) or '无'}）"
    if len(results) < count:
        head += f"；要 {count} 张，能下下来的只有这些"
    out = [head, ""] + lines + [""]
    if attached:
        out.append(f"第 {'、'.join(map(str, attached))} 张附在后面给你看。")
    else:
        out.append("没有附图给你看（图太大或这里收不了图）。")
    if pictures:
        out.append("要给用户看，用 show 工具打开对应的路径。这些图存在用户的图片目录里；用户不要的，删掉就行。")
    else:
        out.append("要给用户看，用 show 工具打开对应的路径。这些图在缓存里，只留最近 10 次搜索；用户要留哪张，拷到工作区或用户说的地方。")
    if failures:
        out.append("没用上的来源：" + "；".join(f"{PROVIDER_NAMES[n]}（{m}）" for n, m in failures.items()))
    print("\n".join(out))


if __name__ == "__main__":
    main()
