#!/usr/bin/env python3
"""Collect public Telegram MTProto proxies, keep only ONLY_COUNTRY (default IR),
save docs/proxies.json and post TOP_N of them to a Telegram channel."""
import html, json, os, random, re, socket, time
import urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, quote, urlparse

OUT_DIR = "docs"
STATE = f"{OUT_DIR}/last_msg.txt"
TOP_N = int(os.getenv("TOP_N", "10"))
MAX_CANDIDATES = 2000
ONLY_COUNTRY = os.getenv("ONLY_COUNTRY", "IR").strip().upper()
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
CHAT_ID = os.getenv("CHAT_ID", "")
GH_TOKEN = os.getenv("GH_TOKEN", "")

SEARCH_QUERIES = [
    "پروکسی تلگرام", "mtproto proxy", "telegram proxy",
    "mtproxy list", "پروکسی",
]
FILE_HINT = re.compile(r"(proxy|proxies|mtproto|mtproxy|telegram|tg)", re.I)
LINK_RE = re.compile(
    r"(?:tg://proxy|https?://t\.me/proxy)\?[^\s\"'<>\)\]]+", re.I)


def http(url, headers=None, timeout=30):
    h = {"User-Agent": "Mozilla/5.0"}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def fetch(url):
    try:
        return http(url)
    except Exception as e:
        print(f"[skip] {url}: {e}")
        return ""


def gh_json(url):
    h = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        h["Authorization"] = "Bearer " + GH_TOKEN
    try:
        return json.loads(http(url, h))
    except Exception as e:
        print(f"[gh skip] {url}: {e}")
        return None


def discover():
    since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    repos = []
    for q in SEARCH_QUERIES:
        url = ("https://api.github.com/search/repositories?q="
               + quote(f"{q} pushed:>{since}")
               + "&sort=updated&order=desc&per_page=20")
        data = gh_json(url)
        time.sleep(2)
        for it in (data or {}).get("items", []):
            if it["full_name"] not in [r[0] for r in repos]:
                repos.append((it["full_name"], it.get("default_branch", "main")))
    repos = repos[:50]
    print(f"discovered repos: {len(repos)}")

    def files_of(repo):
        full, br = repo
        tree = gh_json(f"https://api.github.com/repos/{full}/git/trees/{br}?recursive=1")
        out = []
        for n in (tree or {}).get("tree", []):
            if n.get("type") != "blob" or n.get("size", 0) > 3_000_000:
                continue
            path = n["path"]
            name = path.rsplit("/", 1)[-1]
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext in ("", "txt", "md", "json", "list", "html") and FILE_HINT.search(path):
                out.append(f"https://raw.githubusercontent.com/{full}/{br}/{quote(path)}")
        return out[:8]

    with ThreadPoolExecutor(8) as ex:
        groups = list(ex.map(files_of, repos))
    return [u for g in groups for u in g]


def parse(link):
    try:
        q = parse_qs(urlparse(html.unescape(link)).query)
        server = q["server"][0].strip()
        port = int(q["port"][0])
        secret = q["secret"][0].strip()
    except Exception:
        return None
    if not server or " " in server or not (1 <= port <= 65535) or len(secret) < 32:
        return None
    return server, port, secret


def probe(c):
    """Return (candidate, best_ms) or (candidate, None) if unreachable from here."""
    server, port, _ = c
    best = None
    for _ in range(2):
        t = time.time()
        try:
            with socket.create_connection((server, port), timeout=4):
                pass
        except Exception:
            return c, None
        ms = (time.time() - t) * 1000
        best = ms if best is None else min(best, ms)
    return c, best


def flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())


def resolve(h):
    try:
        return h, socket.gethostbyname(h)
    except Exception:
        return h, None


def countries(hosts):
    with ThreadPoolExecutor(50) as ex:
        ips = {h: ip for h, ip in ex.map(resolve, hosts) if ip}
    uniq = list(set(ips.values()))
    m = {}
    for i in range(0, len(uniq), 100):
        chunk = uniq[i:i + 100]
        try:
            body = json.dumps([{"query": ip, "fields": "countryCode,query"}
                               for ip in chunk]).encode()
            req = urllib.request.Request(
                "http://ip-api.com/batch", data=body,
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                for x in json.loads(r.read()):
                    m[x["query"]] = x.get("countryCode", "")
        except Exception as e:
            print(f"[geo skip] {e}")
        if i + 100 < len(uniq):
            time.sleep(4.5)  # free API limit for batch requests
    return {h: m.get(ip, "") for h, ip in ips.items()}


def tg(method, **params):
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/{method}", data=data)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"[telegram {method}] HTTP {e.code}: {e.read().decode()[:200]}")
        return {"ok": False}
    except Exception as e:
        print(f"[telegram {method}] error: {type(e).__name__}")
        return {"ok": False}


def post(picks):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    lines = ["🔄 <b>پروکسی‌های تلگرام</b>", f"🕒 {now} UTC", ""]
    for i, (url, cc) in enumerate(picks, 1):
        lines.append(f'{i}. <a href="{html.escape(url)}">{flag(cc)} اتصال به پروکسی {i}</a>')
    lines += ["", "⚠️ اگر یکی وصل نشد، بعدی را امتحان کنید."]
    res = tg("sendMessage", chat_id=CHAT_ID, text="\n".join(lines),
             parse_mode="HTML", disable_web_page_preview="true")
    if not res.get("ok"):
        print("post failed")
        return
    new_id = res["result"]["message_id"]
    try:
        old = open(STATE).read().strip()
        if old:
            tg("deleteMessage", chat_id=CHAT_ID, message_id=old)
    except FileNotFoundError:
        pass
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(STATE, "w") as f:
        f.write(str(new_id))
    print(f"posted message {new_id}")


def prio(secret):
    s = secret.lower()
    return 0 if s.startswith("ee") else 1 if s.startswith("dd") else 2


def main():
    urls = discover()
    print(f"files to read: {len(urls)}")
    with ThreadPoolExecutor(16) as ex:
        texts = list(ex.map(fetch, urls))

    seen, cands = set(), []
    for text in texts:
        for link in LINK_RE.findall(html.unescape(text)):
            r = parse(link)
            if r and r not in seen:
                seen.add(r)
                cands.append(r)
    print(f"unique proxies: {len(cands)}")

    random.shuffle(cands)
    cands = cands[:MAX_CANDIDATES]

    geo = countries(sorted({c[0] for c in cands}))
    if ONLY_COUNTRY:
        cands = [c for c in cands if geo.get(c[0]) == ONLY_COUNTRY]
    print(f"after country filter ({ONLY_COUNTRY or 'all'}): {len(cands)}")

    # Testing is OFF by default (domestic-only proxies fail from outside Iran).
    # Set TEST_PROXIES=1 in the workflow to turn it back on.
    tested = os.getenv("TEST_PROXIES", "0") == "1"
    alive = set()
    if tested:
        with ThreadPoolExecutor(100) as ex:
            alive = {c for c, ms in ex.map(probe, cands) if ms is not None}
        print(f"reachable from runner: {len(alive)}")

    def url_of(c):
        return (f"https://t.me/proxy?server={quote(c[0])}&port={c[1]}"
                f"&secret={quote(c[2])}")

    try:
        with open(f"{OUT_DIR}/proxies.json") as f:
            prev = {p["url"] for p in json.load(f)["proxies"]}
    except Exception:
        prev = set()

    # not posted last time first, (reachable first if tested), then ee, dd, others
    random.shuffle(cands)
    cands.sort(key=lambda c: (url_of(c) in prev,
                              (c not in alive) if tested else False,
                              prio(c[2])))

    picks, hosts = [], set()
    for c in cands:
        if c[0] in hosts:
            continue
        hosts.add(c[0])
        picks.append((url_of(c), geo.get(c[0], "")))
        if len(picks) >= TOP_N:
            break

    if len(picks) < 3:
        print("too few proxies; nothing posted")
        return

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(f"{OUT_DIR}/proxies.json", "w") as f:
        json.dump({"updated_utc": time.strftime("%Y-%m-%d %H:%M"),
                   "proxies": [{"url": u, "country": c} for u, c in picks]},
                  f, ensure_ascii=False, indent=1)

    if BOT_TOKEN and CHAT_ID:
        post(picks)
    else:
        print("BOT_TOKEN/CHAT_ID not set; skipping post")


if __name__ == "__main__":
    main()
