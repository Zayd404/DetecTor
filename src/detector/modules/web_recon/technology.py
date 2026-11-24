from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from .domain import normalize_target


def identify_technology(target, timeout=15):
    url = normalize_target(target)

    request = Request(
        url,
        headers={"User-Agent": "DetecTor/1.0"},
        method="GET",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            headers = response.headers

            server = headers.get("Server")
            powered_by = headers.get("X-Powered-By")
            allowed_methods = headers.get("Allow")

            technologies = []

            if server:
                technologies.append({
                    "source": "Server",
                    "value": server,
                })

            if powered_by:
                technologies.append({
                    "source": "X-Powered-By",
                    "value": powered_by,
                })

            return {
                "url": url,
                "status": response.status,
                "technologies": technologies,
                "allowed_methods": (
                    [method.strip() for method in allowed_methods.split(",")]
                    if allowed_methods else []
                ),
                "note": "Identification is based on public HTTP headers only.",
            }

    except HTTPError as error:
        return {"url": url, "status": error.code}

    except (URLError, TimeoutError, OSError) as error:
        return {"url": url, "error": str(error)}
