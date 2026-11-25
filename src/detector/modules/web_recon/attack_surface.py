from .ip_recon import _resolve_domain_raw, _raw_https_get
import socket
import ssl
import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .domain import normalize_target

UA_HEADER = {"User-Agent": "DetecTor-Framework/1.1.0"}


def detect_waf_and_stack(target: str, timeout: int = 10) -> dict:
    url = normalize_target(target)
    req = urllib.request.Request(url, headers=UA_HEADER, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            raw_cookies = resp.headers.get_all("Set-Cookie") or []
            body = resp.read(32768).decode("utf-8", errors="replace").lower()
            status_code = resp.status
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        raw_cookies = exc.headers.get_all("Set-Cookie") or [] if exc.headers else []
        body = exc.read(32768).decode("utf-8", errors="replace").lower() if exc.fp else ""
        status_code = exc.code
    except Exception as exc:
        return {"error": str(exc)}

    # 1. Deteksi WAF / CDN
    waf_cdn = []
    server = headers.get("server", "").lower()
    if "cf-ray" in headers or "cloudflare" in server:
        waf_cdn.append("Cloudflare")
    if "x-amz-cf-id" in headers or "cloudfront" in headers.get("via", "").lower():
        waf_cdn.append("AWS CloudFront")
    if "x-sucuri-id" in headers or "sucuri" in server:
        waf_cdn.append("Sucuri WAF")
    if "x-akamai-transformed" in headers or "akamai" in server:
        waf_cdn.append("Akamai")
    if "x-iinfo" in headers or "incapsula" in headers.get("x-cdn", "").lower():
        waf_cdn.append("Imperva Incapsula")
    if "fastly" in headers.get("x-served-by", "").lower() or "varnish" in headers.get("via", "").lower():
        waf_cdn.append("Fastly / Varnish CDN")

    # 2. Deteksi CMS / Framework dari Header & HTML Body
    stack = []
    if "wp-content/" in body or "wp-includes/" in body:
        stack.append("WordPress CMS")
    if "/_next/static" in body or "__next" in body:
        stack.append("Next.js (React)")
    if "laravel_session" in "".join(raw_cookies).lower():
        stack.append("Laravel PHP")
    if "phpsessid" in "".join(raw_cookies).lower() or ".php" in headers.get("x-powered-by", "").lower():
        stack.append("PHP")
    if "asp.net" in headers.get("x-powered-by", "").lower() or "aspsessionid" in "".join(raw_cookies).lower():
        stack.append("ASP.NET")
    if "x-drupal-cache" in headers or "drupal" in body:
        stack.append("Drupal CMS")

    # 3. Audit Keamanan Cookie
    cookie_audit = []
    for c in raw_cookies[:5]:
        name = c.split("=", 1)[0].strip()
        flags = []
        c_low = c.lower()
        flags.append("HttpOnly:YES" if "httponly" in c_low else "HttpOnly:NO")
        flags.append("Secure:YES" if "secure" in c_low else "Secure:NO")
        cookie_audit.append(f"{name} ({', '.join(flags)})")

    return {
        "http_status": status_code,
        "waf_cdn": waf_cdn or ["None detected (Direct / Unidentified)"],
        "detected_stack": stack or ["No obvious CMS/Framework signature"],
        "cookies": cookie_audit or ["No Set-Cookie headers"],
    }


def check_sensitive_paths(target: str, timeout: int = 5) -> list:
    url = normalize_target(target)
    parsed = urlsplit(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    paths = [
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/.env",
        "/.git/HEAD",
    ]
    findings = []

    for path in paths:
        full_url = base_url + path
        req = urllib.request.Request(full_url, headers=UA_HEADER, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                sample = resp.read(256).decode("utf-8", errors="replace").strip()
                note = "Accessible"
                if path == "/.git/HEAD" and "ref:" in sample:
                    note = "CRITICAL: Git repository exposed!"
                elif path == "/.env" and ("=" in sample and "<html" not in sample.lower()):
                    note = "CRITICAL: Environment file exposed!"
                elif "<html" in sample.lower() and path in ("/.env", "/.git/HEAD"):
                    note = "Soft-404 (HTML returned)"
                findings.append({"path": path, "status": resp.status, "note": note})
        except urllib.error.HTTPError as exc:
            findings.append({"path": path, "status": exc.code, "note": "Protected / Not Found"})
        except Exception:
            findings.append({"path": path, "status": "ERR", "note": "Timeout / Blocked"})

    return findings


def enumerate_subdomains(target: str, timeout: int = 8) -> dict:
    import socket
    import ssl
    url = normalize_target(target)
    hostname = urlsplit(url).hostname or ""
    parts = hostname.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) > 2 else hostname
    subs = set()

    # Sumber 1: HackerTarget API lewat Raw Socket (tanpa pemotongan JSON kurung kurawal)
    try:
        ht_ip = _resolve_domain_raw("://hackertarget.com")
        if ht_ip:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(float(timeout))
            s.connect((ht_ip, 443))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname="://hackertarget.com") as ss:
                req = (
                    f"GET /hostsearch/?q={root_domain} HTTP/1.1\r\n"
                    "Host: ://hackertarget.com\r\n"
                    "User-Agent: DetecTor-Framework/1.1.0\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("utf-8")
                ss.sendall(req)
                chunks = []
                while True:
                    d = ss.recv(4096)
                    if not d:
                        break
                    chunks.append(d)
            raw_ht = b"".join(chunks).decode("utf-8", errors="replace")
            body = raw_ht.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw_ht else raw_ht
            for line in body.splitlines():
                if "," in line:
                    host_part = line.split(",", 1)[0].strip().lower()
                    if host_part.endswith(root_domain) and host_part != root_domain and " " not in host_part:
                        subs.add(host_part)
    except Exception:
        pass

    # Sumber 2: Fallback DNS A-Record Check pada subdomain umum jika API pasif dibatasi
    if not subs:
        common_subs = ("www", "mail", "api", "dev", "staging", "admin", "blog", "cdn", "app", "portal")
        for prefix in common_subs:
            candidate = f"{prefix}.{root_domain}"
            if _resolve_domain_raw(candidate):
                subs.add(candidate)

    sorted_subs = sorted(subs)
    return {
        "root_domain": root_domain,
        "total_found": len(sorted_subs),
        "subdomains": sorted_subs[:20],
    }
