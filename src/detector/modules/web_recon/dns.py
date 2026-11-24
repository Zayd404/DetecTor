import socket

from .domain import normalize_target


def lookup_dns(target):
    url = normalize_target(target)
    hostname = url.split("://", 1)[1].split("/", 1)[0]
    hostname = hostname.split(":", 1)[0].strip("[]")

    results = {
        "domain": hostname,
        "ipv4": [],
        "ipv6": [],
    }

    try:
        records = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for record in records:
            address = record[4][0]

            if ":" in address:
                results["ipv6"].append(address)
            else:
                results["ipv4"].append(address)

    except socket.gaierror as error:
        results["error"] = str(error)

    results["ipv4"] = sorted(set(results["ipv4"]))
    results["ipv6"] = sorted(set(results["ipv6"]))

    return results
