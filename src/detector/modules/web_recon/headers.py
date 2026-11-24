from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse

from .domain import normalize_target


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


RECOMMENDATIONS = {
    "strict-transport-security":
        "Gunakan HTTPS dan konfigurasi HSTS.",
    "content-security-policy":
        "Pertimbangkan Content Security Policy untuk membatasi sumber konten.",
    "x-content-type-options":
        "Tambahkan X-Content-Type-Options: nosniff.",
    "x-frame-options":
        "Atur perlindungan framing melalui X-Frame-Options atau CSP frame-ancestors.",
    "referrer-policy":
        "Atur Referrer-Policy sesuai kebutuhan privasi.",
    "permissions-policy":
        "Batasi fitur browser yang tidak diperlukan melalui Permissions-Policy.",
}


def analyze_security_headers(headers, scheme):
    analysis = {}
    present = 0
    missing = 0
    not_applicable = 0
    invalid = 0

    for name in SECURITY_HEADERS:
        value = headers.get(name)

        if name == "strict-transport-security" and scheme != "https":
            status = "NOT_APPLICABLE"
            recommendation = "Aktifkan HTTPS sebelum menerapkan HSTS."
            not_applicable += 1

        elif value:
            if name == "strict-transport-security":
                max_age_values = []

                for directive in value.split(";"):
                    key, separator, directive_value = (
                        directive.strip().partition("=")
                    )

                    if key.strip().lower() == "max-age":
                        max_age_values.append(
                            directive_value.strip()
                            if separator else ""
                        )

                valid = (
                    len(max_age_values) == 1
                    and max_age_values[0].isdigit()
                )

            elif name == "x-content-type-options":
                valid = value.strip().lower() == "nosniff"

            elif name == "referrer-policy":
                policies = [
                    item.strip().lower()
                    for item in value.split(",")
                ]
                valid = any(
                    item in VALID_REFERRER_POLICIES
                    for item in policies
                )

            elif name in (
                "content-security-policy",
                "permissions-policy",
            ):
                valid = bool(value.strip())

            else:
                valid = True

            if valid:
                status = "PRESENT"
                recommendation = None
                present += 1
            else:
                status = "INVALID"
                recommendation = RECOMMENDATIONS[name]
                invalid += 1
        else:
            status = "MISSING"
            recommendation = RECOMMENDATIONS[name]
            missing += 1

        analysis[name] = {
            "status": status,
            "recommendation": recommendation,
        }

    return {
        "headers": analysis,
        "summary": {
            "present": present,
            "missing": missing,
            "not_applicable": not_applicable,
            "invalid": invalid,
        },
    }


def inspect_headers(target, timeout=15):
    url = normalize_target(target)
    scheme = urlparse(url).scheme

    def make_request(method):
        request = Request(
            url,
            headers={"User-Agent": "DetecTor/1.0"},
            method=method,
        )

        with urlopen(request, timeout=timeout) as response:
            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            security_headers = {
                name: headers.get(name)
                for name in SECURITY_HEADERS
            }

            return {
                "url": url,
                "status": response.status,
                "method": method,
                "security_headers": security_headers,
                "security_analysis": analyze_security_headers(
                    security_headers, scheme
                ),
            }

    try:
        try:
            return make_request("HEAD")

        except HTTPError as error:
            if error.code not in (405, 501):
                return {
                    "url": url,
                    "status": error.code,
                    "error": "HTTP request returned an error status.",
                }

            error.close()
            return make_request("GET")

    except HTTPError as error:
        return {
            "url": url,
            "status": error.code,
            "error": "HTTP request returned an error status.",
        }

    except (URLError, TimeoutError, OSError) as error:
        return {
            "url": url,
            "error": str(error),
        }
