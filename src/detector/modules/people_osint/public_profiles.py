import json
import re
import socket
import ssl
from urllib.parse import urlsplit, urlunsplit

from .username import validate_username
from ..web_recon.ip_recon import _resolve_domain_raw, _raw_https_get


PLATFORM_SPECS = {
    "GitHub": ("github.com", "/{u}", "", "github.com", "/{u}", "status"),
    "GitLab": ("gitlab.com", "/api/v4/users", "username={u}", "gitlab.com", "/{u}", "json_nonempty"),
    "Reddit": ("://reddit.com", "/user/{u}/about.json", "", "://reddit.com", "/user/{u}/", "reddit"),
    "Dev.to": ("dev.to", "/api/users/by_username", "url={u}", "dev.to", "/{u}", "json_id"),
    "Medium": ("medium.com", "/@{u}", "", "medium.com", "/@{u}", "status"),
    "Pastebin": ("pastebin.com", "/u/{u}", "", "pastebin.com", "/u/{u}", "status"),
    "Pinterest": ("://pinterest.com", "/{u}/", "", "://pinterest.com", "/{u}/", "status"),
    "Linktree": ("linktr.ee", "/{u}", "", "linktr.ee", "/{u}", "status"),
    "Keybase": ("keybase.io", "/{u}", "", "keybase.io", "/{u}", "status"),
    "TikTok": ("://tiktok.com", "/@{u}", "", "://tiktok.com", "/@{u}", "link_only"),
    "Instagram": ("://instagram.com", "/{u}/", "", "://instagram.com", "/{u}/", "link_only"),
    "X": ("x.com", "/{u}", "", "x.com", "/{u}", "link_only"),
}


def _probe_url_raw(url: str, timeout: float = 5.0) -> tuple:
    parsed = urlsplit(url)
    host = parsed.hostname
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    ip = _resolve_domain_raw(host)
    if not ip:
        return (0, "")
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
            req = (
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36\r\n"
                "Accept: text/html,application/json;q=0.9,*/*;q=0.8\r\nConnection: close\r\n\r\n"
            ).encode("utf-8")
            ssock.sendall(req)
            chunks = []
            total = 0
            while total < 32768:
                data = ssock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
        raw_resp = b"".join(chunks).decode("utf-8", errors="replace")
        header_part, _, body_part = raw_resp.partition("\r\n\r\n")
        lines = header_part.splitlines()
        first_line = next(iter(lines), "")
        parts = first_line.split(" ")
        code_str = parts.pop(1) if len(parts) > 1 else "0"
        code = int(code_str) if code_str.isdigit() else 0
        return (code, body_part)
    except Exception:
        return (0, "")


def _fetch_github_intel(username: str) -> dict:
    try:
        gh_ip = _resolve_domain_raw("api.github.com")
        if not gh_ip:
            return {}
        api_path = urlunsplit(("", "", f"/users/{username}", "", ""))
        data = json.loads(_raw_https_get(gh_ip, "api.github.com", api_path, timeout=6.0))
        if not data.get("login"):
            return {}
        intel = {
            "platform": "GitHub", "name": data.get("name") or "-",
            "bio": (data.get("bio") or "-").replace("\n", " "),
            "company": data.get("company") or "-", "location": data.get("location") or "-",
            "blog": data.get("blog") or "-", "public_email": data.get("email") or "-",
            "public_repos": data.get("public_repos", 0), "followers": data.get("followers", 0),
            "created_at": (data.get("created_at") or "-")[:10], "commit_emails": [],
        }
        try:
            ev_path = urlunsplit(("", "", f"/users/{username}/events/public", "per_page=15", ""))
            raw_ev = _raw_https_get(gh_ip, "api.github.com", ev_path, timeout=5.0)
            emails = {em for em in re.findall(r'"email"\s*:\s*"([^"]+@[^"]+)"', raw_ev) if "noreply.github.com" not in em.lower()}
            intel["commit_emails"] = sorted(emails)
        except Exception:
            pass
        return intel
    except Exception:
        return {}


def _fetch_gitlab_intel(username: str) -> dict:
    try:
        gl_ip = _resolve_domain_raw("gitlab.com")
        if not gl_ip:
            return {}
        gl_path = urlunsplit(("", "", "/api/v4/users", f"username={username}", ""))
        raw_gl = _raw_https_get(gl_ip, "gitlab.com", gl_path, timeout=6.0)
        uid_m = re.search(r'"id"\s*:\s*(\d+)', raw_gl)
        name_m = re.search(r'"name"\s*:\s*"([^"]+)"', raw_gl)
        state_m = re.search(r'"state"\s*:\s*"([^"]+)"', raw_gl)
        if uid_m:
            return {"platform": "GitLab", "user_id": uid_m.group(1), "name": name_m.group(1) if name_m else "-", "state": state_m.group(1) if state_m else "-"}
    except Exception:
        pass
    return {}


def generate_profile_links(username: str) -> dict:
    validation = validate_username(username)
    if not validation["valid"]:
        return {"valid": False, "username": username, "error": validation["message"], "profiles": {}}

    username = validation["username"]
    results = {}
    found_count = 0

    for platform, (p_host, p_path, p_q, d_host, d_path, mode) in PLATFORM_SPECS.items():
        probe_url = urlunsplit(("https", p_host, p_path.format(u=username), p_q.format(u=username), ""))
        display_url = urlunsplit(("https", d_host, d_path.format(u=username), "", ""))

        if mode == "link_only":
            results[platform] = {"status": "MANUAL CHECK", "url": display_url}
            continue
        code, body = _probe_url_raw(probe_url)
        if mode == "status":
            if code == 200:
                results[platform] = {"status": "FOUND", "url": display_url}
                found_count += 1
            elif code in (301, 302, 404):
                results[platform] = {"status": "NOT FOUND", "url": display_url}
            else:
                results[platform] = {"status": f"UNKNOWN ({code or 'ERR'})", "url": display_url}
        elif mode == "json_nonempty":
            if code == 200 and '"username"' in body:
                results[platform] = {"status": "FOUND", "url": display_url}
                found_count += 1
            elif code in (200, 404):
                results[platform] = {"status": "NOT FOUND", "url": display_url}
            else:
                results[platform] = {"status": f"UNKNOWN ({code or 'ERR'})", "url": display_url}
        elif mode == "reddit":
            if code == 200 and '"kind": "t2"' in body:
                results[platform] = {"status": "FOUND", "url": display_url}
                found_count += 1
            elif code == 404:
                results[platform] = {"status": "NOT FOUND", "url": display_url}
            else:
                results[platform] = {"status": "MANUAL CHECK", "url": display_url}
        elif mode == "json_id":
            if code == 200 and '"username"' in body:
                results[platform] = {"status": "FOUND", "url": display_url}
                found_count += 1
            else:
                results[platform] = {"status": "NOT FOUND", "url": display_url}

    gh_intel = _fetch_github_intel(username) if results.get("GitHub", {}).get("status") == "FOUND" else {}
    gl_intel = _fetch_gitlab_intel(username) if results.get("GitLab", {}).get("status") == "FOUND" else {}

    return {
        "valid": True, "username": username, "found_count": found_count,
        "profiles": results, "github_intel": gh_intel, "gitlab_intel": gl_intel,
    }
