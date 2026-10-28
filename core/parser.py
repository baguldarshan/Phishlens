import ipaddress
from urllib.parse import parse_qsl, urlsplit


class URLParseError(ValueError):
    """Raised when a URL cannot be safely analyzed."""


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def parse_url(value: str) -> dict:
    if not isinstance(value, str) or not value.strip():
        raise URLParseError("Enter a URL to analyze.")
    submitted = value.strip()
    if len(submitted) > 2048:
        raise URLParseError("The URL must be 2,048 characters or fewer.")
    candidate = submitted if "://" in submitted else f"https://{submitted}"
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        port = parts.port
    except (ValueError, UnicodeError) as exc:
        raise URLParseError("That URL is malformed or contains an invalid port.") from exc
    if parts.scheme not in {"http", "https"} or not hostname:
        raise URLParseError("Only HTTP and HTTPS URLs with a hostname can be analyzed.")
    hostname = hostname.lower().rstrip(".")
    is_ip = _is_ip(hostname)
    labels = hostname.split(".")
    registered_domain = hostname if is_ip or len(labels) < 2 else ".".join(labels[-2:])
    subdomain = "" if is_ip or len(labels) < 3 else ".".join(labels[:-2])
    return {
        "original_url": submitted,
        "normalized_url": parts.geturl(),
        "scheme": parts.scheme,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "top_level_domain": "" if is_ip or "." not in hostname else labels[-1],
        "port": port,
        "path": parts.path or "/",
        "query_parameters": len(parse_qsl(parts.query, keep_blank_values=True)),
        "has_userinfo": bool(parts.username or parts.password),
        "is_ip_hostname": is_ip,
        "url_length": len(submitted),
        "has_percent_encoding": "%" in submitted,
        "fragment_present": bool(parts.fragment),
    }
