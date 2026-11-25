import os
import platform
import shutil
import socket
import ssl
import sys
from pathlib import Path


def _get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return str(next(iter(s.getsockname())))
    except Exception:
        return "Unavailable"


def _get_public_exit_ip() -> tuple:
    # Cek koneksi internet & Public IP via Cloudflare trace (1.1.1.1)
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(3.0)
        raw.connect(("1.1.1.1", 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(raw, server_hostname="1.1.1.1") as ss:
            req = (
                "GET /cdn-cgi/trace HTTP/1.1\r\n"
                "Host: 1.1.1.1\r\n"
                "User-Agent: DetecTor-Framework/1.1.0\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")
            ss.sendall(req)
            resp = ss.recv(2048).decode("utf-8", errors="replace")
            for line in resp.splitlines():
                if line.startswith("ip="):
                    return ("ONLINE", line.partition("=")[-1].strip())
        return ("ONLINE", "Unknown")
    except Exception:
        return ("OFFLINE", "Not Connected")


def _get_storage_summary() -> str:
    try:
        total, used, free = shutil.disk_usage(Path.cwd())
        free_gb = free / (1024 ** 3)
        total_gb = total / (1024 ** 3)
        return f"{free_gb:.2f} GB free / {total_gb:.2f} GB total"
    except Exception:
        return "Unavailable"


def _count_saved_reports() -> str:
    rep_dir = Path("reports")
    if not rep_dir.exists():
        return "0 files (reports/ not created yet)"
    files = [f for f in rep_dir.iterdir() if f.is_file()]
    return f"{len(files)} files in reports/"


def get_system_info():
    net_status, public_ip = _get_public_exit_ip()
    is_termux = "com.termux" in sys.executable or "TERMUX_VERSION" in os.environ
    env_label = "Termux (Android)" if is_termux else platform.system()

    return {
        "python_version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "environment": env_label,
        "machine": platform.machine(),
        "platform": platform.platform(),
        "executable": sys.executable,
        "local_ip": _get_local_ip(),
        "network_status": net_status,
        "public_ip": public_ip,
        "storage": _get_storage_summary(),
        "saved_reports": _count_saved_reports(),
    }
