import ipaddress
import json
import socket
import ssl
from urllib.parse import urlsplit


def normalize_ip_target(target: str) -> str:
    cleaned = target.strip()
    candidate = cleaned if "://" in cleaned else f"http://{cleaned}"
    host = urlsplit(candidate).hostname or cleaned.strip("[]")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        raise ValueError(f"Format alamat IP tidak valid: '{target}'")


def _raw_https_get(ip: str, host_header: str, path: str, timeout: float = 6.0) -> str:
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)
    raw_sock.connect((ip, 443))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with ctx.wrap_socket(raw_sock, server_hostname=host_header) as ssock:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: DetecTor-Framework/1.1.0\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        ssock.sendall(req)
        chunks = []
        while True:
            data = ssock.recv(4096)
            if not data:
                break
            chunks.append(data)
    raw_resp = b"".join(chunks).decode("utf-8", errors="replace")
    body = raw_resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw_resp else raw_resp
    start = body.find("{")
    end = body.rfind("}")
    return body[start : end + 1] if start != -1 and end != -1 else body


def _raw_http_get(ip: str, host_header: str, path: str, timeout: float = 6.0) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((ip, 80))
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: DetecTor-Framework/1.1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(req)
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    raw_resp = b"".join(chunks).decode("utf-8", errors="replace")
    body = raw_resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw_resp else raw_resp
    start = body.find("{")
    end = body.rfind("}")
    return body[start : end + 1] if start != -1 and end != -1 else body


def _resolve_domain_raw(hostname: str) -> str:
    for dns_ip in ("8.8.8.8", "1.1.1.1"):
        try:
            sni = "dns.google" if dns_ip == "8.8.8.8" else "cloudflare-dns.com"
            path = f"/resolve?name={hostname}&type=A" if dns_ip == "8.8.8.8" else f"/dns-query?name={hostname}&type=A"
            raw_json = _raw_https_get(dns_ip, sni, path, timeout=4.0)
            data = json.loads(raw_json)
            for ans in data.get("Answer", []):
                if ans.get("type") == 1:
                    return ans.get("data")
        except Exception:
            continue
    return ""


def _whois_ip_fallback(ip_str: str) -> dict:
    # Pure TCP Port 43 WHOIS query langsung ke IP ARIN (199.71.0.46) tanpa DNS
    info = {"isp": "-", "org": "-", "as": "-", "country": "-", "city": "-", "regionName": "-"}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect(("199.71.0.46", 43))
            s.sendall(f"n + {ip_str}\r\n".encode("ascii"))
            out = []
            while True:
                d = s.recv(4096)
                if not d:
                    break
                out.append(d)
        text = b"".join(out).decode("utf-8", errors="replace")
        for line in text.splitlines():
            low = line.lower()
            if low.startswith("orgname:") or low.startswith("descr:"):
                if info["org"] == "-":
                    info["org"] = line.split(":", 1)[1].strip()
                    info["isp"] = info["org"]
            elif low.startswith("originas:"):
                info["as"] = line.split(":", 1)[1].strip()
            elif low.startswith("country:"):
                info["country"] = line.split(":", 1)[1].strip()
            elif low.startswith("city:"):
                info["city"] = line.split(":", 1)[1].strip()
            elif low.startswith("stateprov:"):
                info["regionName"] = line.split(":", 1)[1].strip()
        info["timezone"] = "WHOIS Direct (TCP/43)"
        info["lat"] = "-"
        info["lon"] = "-"
        return info
    except Exception as exc:
        return {"error": str(exc)}


def inspect_ip_network(ip_str: str) -> dict:
    ip_obj = ipaddress.ip_address(ip_str)
    network_info = {
        "ip": ip_str,
        "version": f"IPv{ip_obj.version}",
        "is_private": ip_obj.is_private,
        "is_global": ip_obj.is_global,
        "is_loopback": ip_obj.is_loopback,
        "reverse_dns": "No PTR record",
    }
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        network_info["reverse_dns"] = hostname
    except Exception:
        pass
    return network_info


def lookup_ip_geolocation(ip_str: str) -> dict:
    ip_obj = ipaddress.ip_address(ip_str)
    if not ip_obj.is_global:
        return {"note": "Geolocation skipped (Non-public / Private IP)."}
    try:
        api_ip = _resolve_domain_raw("ip-api.com")
        if api_ip:
            path = f"/json/{ip_str}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,proxy,hosting"
            data = json.loads(_raw_http_get(api_ip, "ip-api.com", path))
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return _whois_ip_fallback(ip_str)


def _verify_port_service(ip_str: str, port: int, timeout: float = 1.5) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip_str, port))
        with sock:
            if port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=ip_str) as ssock:
                    return f"TLS ({ssock.version()})"
            if port in (80, 8080, 8000, 8888):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            elif port == 53:
                sock.sendall(b"\x00\x1c\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01")
            data = sock.recv(128)
            if not data:
                return ""
            if port == 53 and len(data) > 4:
                return "DNS Service Active"
            text = data.decode("utf-8", errors="replace").strip()
            first_line = text.splitlines()[0] if text else ""
            return first_line[:65] if first_line else "Active Binary Service"
    except Exception:
        return ""


def lookup_passive_exposure(ip_str: str) -> dict:
    ip_obj = ipaddress.ip_address(ip_str)
    if not ip_obj.is_global:
        return {"note": "Passive exposure skipped (Non-public IP)."}
    try:
        shodan_ip = _resolve_domain_raw("internetdb.shodan.io")
        if shodan_ip:
            data = json.loads(_raw_https_get(shodan_ip, "internetdb.shodan.io", f"/{ip_str}"))
            if "ports" in data:
                ports = data.get("ports", [])
                banners = {}
                for p in ports[:6]:
                    svc = _verify_port_service(ip_str, int(p))
                    if svc:
                        banners[str(p)] = svc
                return {
                    "ports": ports,
                    "banners": banners,
                    "hostnames": data.get("hostnames", []),
                    "tags": data.get("tags", []),
                    "cpes": data.get("cpes", []),
                    "vulns": data.get("vulns", []),
                }
    except Exception:
        pass

    common_ports = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443)
    verified_ports = []
    banners = {}
    for p in common_ports:
        svc = _verify_port_service(ip_str, p)
        if svc:
            verified_ports.append(p)
            banners[str(p)] = svc
    return {
        "ports": verified_ports,
        "banners": banners,
        "hostnames": ["Verified Active Service Scan"],
        "tags": ["service-verified"],
        "vulns": [],
    }


def probe_direct_http(ip_str: str) -> dict:
    services = {}
    for scheme, port in (("HTTP", 80), ("HTTPS", 443)):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4.0)
            sock.connect((ip_str, port))
            if scheme == "HTTPS":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ctx.wrap_socket(sock, server_hostname=ip_str)
            else:
                conn = sock
            with conn:
                req = f"HEAD / HTTP/1.1\r\nHost: {ip_str}\r\nUser-Agent: DetecTor-Framework/1.1.0\r\nConnection: close\r\n\r\n".encode("utf-8")
                conn.sendall(req)
                resp = conn.recv(2048).decode("utf-8", errors="replace")
                lines = resp.splitlines()
                status = lines[0].split(" ", 2)[1] if lines and len(lines[0].split(" ")) > 1 else "200"
                server = "Hidden / Unknown"
                for line in lines[1:]:
                    if line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                        break
                services[scheme] = {"status": status, "server": server}
        except Exception:
            services[scheme] = {"status": "Closed / Filtered", "server": "-"}
    return services
