import socket
import ssl
import time

from urllib.parse import urlsplit

from .domain import normalize_target



def analyze_tls_version(version):
    grades = {
        "TLSv1.3": "GOOD",
        "TLSv1.2": "ACCEPTABLE",
        "TLSv1.1": "OUTDATED",
        "TLSv1": "OUTDATED",
    }

    return grades.get(version, "UNKNOWN")


def analyze_certificate_validity(valid_from, valid_until):
    if not valid_from or not valid_until:
        return "UNKNOWN"

    try:
        start = ssl.cert_time_to_seconds(valid_from)
        expiry = ssl.cert_time_to_seconds(valid_until)
        now = time.time()

        if start > expiry:
            return "UNKNOWN"

        if now < start:
            return "NOT_YET_VALID"

        if now >= expiry:
            return "EXPIRED"

        if expiry - now <= 30 * 24 * 60 * 60:
            return "EXPIRING_SOON"

        return "VALID"

    except (ValueError, TypeError, OverflowError):
        return "UNKNOWN"


def get_certificate_days_remaining(valid_until):
    if not valid_until:
        return None

    try:
        expiry = ssl.cert_time_to_seconds(valid_until)
        remaining = expiry - time.time()

        return int(remaining / (24 * 60 * 60))

    except (ValueError, TypeError, OverflowError):
        return None

def inspect_ssl(target, timeout=15):
    url = normalize_target(target)
    parsed = urlsplit(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as connection:
            with context.wrap_socket(
                connection,
                server_hostname=hostname,
            ) as secure_socket:
                certificate = secure_socket.getpeercert()
                tls_version = secure_socket.version()
                valid_from = certificate.get("notBefore")
                valid_until = certificate.get("notAfter")
                certificate_grade = analyze_certificate_validity(
                    valid_from,
                    valid_until,
                )

                return {
                    "domain": hostname,
                    "tls_version": tls_version,
                    "tls_grade": analyze_tls_version(tls_version),
                    "certificate_grade": certificate_grade,
                    "issuer": certificate.get("issuer"),
                    "subject": certificate.get("subject"),
                    "valid_from": valid_from,
                    "valid_until": valid_until,
                    "days_remaining": get_certificate_days_remaining(
                        valid_until
                    ),
                }

    except (OSError, ssl.SSLError, ValueError) as error:
        return {
            "domain": hostname,
            "error": str(error),
        }
