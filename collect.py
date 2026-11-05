#!/usr/bin/env python3
"""Collect public proxy configs (Iranian repos first), test with xray,
publish a base64 subscription to docs/sub.txt.
Supports vless / vmess / trojan (TLS or Reality) and shadowsocks (no plugin)."""
import base64, json, os, random, re, socket, subprocess, tempfile
import threading, time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs, unquote, quote

OUT_DIR = "docs"
TOP_N = int(os.getenv("TOP_N", "120"))
MAX_CANDIDATES = int(os.getenv("MAX_CANDIDATES", "1500"))
IRAN_SHARE = 0.7
WORKERS = int(os.getenv("WORKERS", "30"))
MAX_PER_HOST = 2
CURL_TIMEOUT = 8
GH_TOKEN = os.getenv("GH_TOKEN", "")

REQUIRED = [
    "https://www.youtube.com/generate_204",
    "https://web.telegram.org/",
    "https://www.instagram.com/",
]
OPTIONAL = [
    "https://claude.ai/",
    "https://labs.google/",
]

# Persian / Iranian-flavoured queries first
SEARCH_QUERIES = [
    "فیلترشکن", "کانفیگ v2ray", "v2ray ایران", "vless iran",
    "persian v2ray", "iran v2ray config", "free v2ray subscription",
]
FILE_HINT = re.compile(
    r"(sub|config|v2ray|vless|vmess|trojan|mix|all|proxy|reality|ss|normal)", re.I)

SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "chacha20-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}

_lock = threading.Lock()
_port = [20000]


def next_port():
    with _lock:
        _port[0] += 1
        return _port[0]


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


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
    """Find raw file URLs inside recently-updated GitHub repos."""
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
    repos = repos[:60]
    print(f"discovered repos: {len(repos)}")

    def files_of(repo):
        full, br = repo
        tree = gh_json(f"https://api.github.com/repos/{full}/git/trees/{br}?recursive=1")
        out = []
        for n in (tree or {}).get("tree", []):
            if n.get("type") != "blob" or n.get("size", 0) > 4_000_000:
                continue
            path = n["path"]
            name = path.rsplit("/", 1)[-1]
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext in ("", "txt", "yaml", "yml", "json", "md") and FILE_HINT.search(path):
                out.append(f"https://raw.githubusercontent.com/{full}/{br}/{quote(path)}")
        return out[:8]

    with ThreadPoolExecutor(8) as ex:
        groups = list(ex.map(files_of, repos))
    return [u for g in groups for u in g]


LINK_RE = re.compile(r"(?<![A-Za-z0-9])(?:vless|vmess|trojan|ss)://[^\s\"'<>]+")


def extract_links(text):
    text = text.strip()
    links = LINK_RE.findall(text)
    if not links:
        try:
            links = LINK_RE.findall(b64d(text))
        except Exception:
            links = []
    return links


def parse_ss(link):
    body = link[5:].split("#", 1)[0]
    if "?" in body:
        body, query = body.split("?", 1)
        if "plugin" in query:
            return None
    body = body.rstrip("/")
    if "@" in body:
        userinfo, hp = body.rsplit("@", 1)
        ui = unquote(userinfo)
        cred = ui if ":" in ui else b64d(userinfo)
    else:
        cred, hp = b64d(body).rsplit("@", 1)
    method, password = cred.split(":", 1)
    host, port = hp.rsplit(":", 1)
    host = host.strip("[]")
    port = int(port.strip("/"))
    if method not in SS_METHODS:
        return None
    outbound = {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port,
                                  "method": method, "password": password}]},
        "streamSettings": {"network": "tcp"},
    }
    return ("ss", host, port, password, method), outbound, host, port


def parse(link):
    """Return (key, xray_outbound, host, port) or None."""
    try:
        scheme = link.split("://", 1)[0]
        if scheme == "ss":
            return parse_ss(link)

        if scheme == "vmess":
            d = json.loads(b64d(link[8:]))
            host, port = d["add"], int(d["port"])
            net = d.get("net", "tcp")
            if d.get("tls") != "tls":
                return None
            if d.get("allowInsecure") in (1, "1", True, "true"):
                return None
            q = {
                "sni": d.get("sni") or d.get("host") or host,
                "path": d.get("path", "/"),
                "host": d.get("host", ""),
                "serviceName": d.get("path", ""),
                "fp": d.get("fp", "chrome"),
                "alpn": d.get("alpn", ""),
            }
            user = {"id": d["id"], "alterId": int(d.get("aid", 0)), "security": "auto"}
            proto = "vmess"
            settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
            security = "tls"
            ident = d["id"]
        else:
            u = urlparse(link)
            host, port = u.hostname, u.port
            if not host or not port:
                return None
            qs = {k: v[0] for k, v in parse_qs(u.query).items()}
            net = qs.get("type", "tcp")
            security = qs.get("security", "none")
            if security not in ("tls", "reality"):
                return None
            if qs.get("allowInsecure") in ("1", "true") or qs.get("insecure") in ("1", "true"):
                return None
            q = {
                "sni": qs.get("sni") or qs.get("host") or host,
                "path": unquote(qs.get("path", "/")),
                "host": qs.get("host", ""),
                "serviceName": qs.get("serviceName", ""),
                "fp": qs.get("fp", "chrome"),
                "alpn": qs.get("alpn", ""),
                "pbk": qs.get("pbk", ""),
                "sid": qs.get("sid", ""),
                "spx": qs.get("spx", ""),
            }
            ident = unquote(u.username or "")
            if not ident:
                return None
            if scheme == "vless":
                user = {"id": ident, "encryption": "none"}
                if qs.get("flow"):
                    user["flow"] = qs["flow"]
                proto = "vless"
                settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
            elif scheme == "trojan":
                proto = "trojan"
                settings = {"servers": [{"address": host, "port": port, "password": ident}]}
            else:
                return None

        if net not in ("tcp", "ws", "grpc"):
            return None

        stream = {"network": net, "security": security}
        if security == "tls":
            tls = {"serverName": q["sni"], "fingerprint": q.get("fp") or "chrome"}
            if q.get("alpn"):
                tls["alpn"] = q["alpn"].split(",")
            stream["tlsSettings"] = tls
        else:
            if not q.get("pbk"):
                return None
            stream["realitySettings"] = {
                "serverName": q["sni"],
                "fingerprint": q.get("fp") or "chrome",
                "publicKey": q["pbk"],
                "shortId": q.get("sid", ""),
                "spiderX": q.get("spx", ""),
            }
        if net == "ws":
            ws = {"path": q["path"]}
            if q["host"]:
                ws["headers"] = {"Host": q["host"]}
            stream["wsSettings"] = ws
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": q["serviceName"]}

        outbound = {"protocol": proto, "settings": settings, "streamSettings": stream}
        key = (scheme, host, port, ident, net, q.get("path"), q.get("serviceName"))
        return key, outbound, host, port
    except Exception:
        return None


def tcp_alive(host, port):
    try:
        with socket.create_connection((host, port), timeout=4):
            return True
    except Exception:
        return False


def curl(port, url):
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
             "--socks5-hostname", f"127.0.0.1:{port}",
             "--max-time", str(CURL_TIMEOUT), url],
            capture_output=True, text=True, timeout=CURL_TIMEOUT + 3)
        code, t = r.stdout.split()
        return code != "000", float(t)
    except Exception:
        return False, 99.0


def test(item):
    link, outbound, host = item
    port = next_port()
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"udp": False}}],
        "outbounds": [outbound],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        path = f.name
    p = subprocess.Popen(["xray", "run", "-c", path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):
            if tcp_alive("127.0.0.1", port):
                break
            time.sleep(0.1)
        else:
            return None
        total = 0.0
        for url in REQUIRED:
            ok, t = curl(port, url)
            if not ok:
                return None
            total += t
        score = len(REQUIRED)
        for url in OPTIONAL:
            ok, _ = curl(port, url)
            score += 1 if ok else 0
        return link, score, total / len(REQUIRED), host
    finally:
        p.kill()
        try:
            os.unlink(path)
        except OSError:
            pass


def rename(link, name):
    if link.startswith("vmess://"):
        d = json.loads(b64d(link[8:]))
        d["ps"] = name
        return "vmess://" + base64.b64encode(json.dumps(d).encode()).decode()
    return link.split("#", 1)[0] + "#" + quote(name)


def main():
    manual = [l.strip() for l in open("sources.txt")
              if l.strip() and not l.startswith("#")]
    found = discover()
    print(f"discovered files: {len(found)}, manual sources: {len(manual)}")

    urls = [(u, True) for u in found] + [(u, False) for u in manual]
    with ThreadPoolExecutor(16) as ex:
        texts = list(ex.map(lambda x: fetch(x[0]), urls))

    seen, iran, other = set(), [], []
    for (url, is_iran), text in zip(urls, texts):
        for link in extract_links(text):
            r = parse(link)
            if not r:
                continue
            key, outbound, host, port = r
            if key in seen:
                continue
            seen.add(key)
            (iran if is_iran else other).append((link, outbound, host, port))
    print(f"candidates: iran-repos={len(iran)} other={len(other)}")

    random.shuffle(iran)
    random.shuffle(other)
    n_iran = int(MAX_CANDIDATES * IRAN_SHARE)
    cands = iran[:n_iran] + other[:MAX_CANDIDATES - min(len(iran), n_iran)]

    with ThreadPoolExecutor(100) as ex:
        alive = list(ex.map(lambda c: tcp_alive(c[2], c[3]), cands))
    cands = [c for c, a in zip(cands, alive) if a]
    print(f"tcp reachable: {len(cands)}")

    with ThreadPoolExecutor(WORKERS) as ex:
        results = [r for r in ex.map(test, [(c[0], c[1], c[2]) for c in cands]) if r]
    print(f"passed full test: {len(results)}")

    results.sort(key=lambda r: (-r[1], r[2]))
    per_host, final = {}, []
    for link, score, lat, host in results:
        if per_host.get(host, 0) >= MAX_PER_HOST:
            continue
        per_host[host] = per_host.get(host, 0) + 1
        final.append((link, score, lat))
        if len(final) >= TOP_N:
            break

    os.makedirs(OUT_DIR, exist_ok=True)
    if not final:
        print("nothing passed; keeping previous sub.txt")
        return
    lines = [rename(l, f"W{i+1:03d}-{int(lat*1000)}ms-s{s}")
             for i, (l, s, lat) in enumerate(final)]
    with open(f"{OUT_DIR}/sub.txt", "w") as f:
        f.write(base64.b64encode("\n".join(lines).encode()).decode())
    with open(f"{OUT_DIR}/stats.json", "w") as f:
        json.dump({"updated_utc": time.strftime("%Y-%m-%d %H:%M"),
                   "count": len(final)}, f)
    print(f"published {len(final)} configs")


if __name__ == "__main__":
    main()
