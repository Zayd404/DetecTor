import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


class DomainValidationError(ValueError):
    pass


def normalize_target(value):
    if not isinstance(value, str) or not value.strip():
        raise DomainValidationError("Target tidak boleh kosong.")

    value = value.strip()

    if any(char.isspace() for char in value):
        raise DomainValidationError("Target tidak boleh mengandung spasi.")

    candidate = value if "://" in value else f"https://{value}"

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname

        if parsed.scheme not in ("http", "https") or not hostname:
            raise DomainValidationError("Format URL tidak valid.")

        if parsed.username or parsed.password:
            raise DomainValidationError("URL dengan kredensial tidak diizinkan.")

        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            hostname = hostname.encode("idna").decode("ascii").lower()
            if len(hostname) > 253 or not re.fullmatch(
                r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
                hostname,
            ):
                raise DomainValidationError("Nama domain tidak valid.")

        port = parsed.port
        netloc = f"[{hostname}]" if ":" in hostname else hostname

        if port is not None:
            netloc += f":{port}"

        return urlunsplit((
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        ))

    except ValueError as error:
        if isinstance(error, DomainValidationError):
            raise
        raise DomainValidationError("Format target tidak valid.") from error
