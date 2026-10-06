import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or re.search(r"[\s\x00-\x1f\x7f\\]", value):
        raise ValueError("target must be a domain or HTTP(S) URL without spaces or controls")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("only HTTP(S) targets are supported")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing credentials are not accepted")
    host = parts.hostname.encode("idna").decode().lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            raise ValueError("invalid hostname") from None
    authority = f"[{host}]" if ":" in host else host
    if parts.port is not None:
        authority += f":{parts.port}"
    return urlunsplit((parts.scheme, authority, parts.path or "/", parts.query, ""))


def load_targets(values, lists, stdin, max_targets=1000):
    seen = set()
    used_stdin = False
    for value, is_file in [(v, False) for v in values] + [(v, True) for v in lists]:
        if is_file or value == "-" or ("://" not in value and Path(value).is_file()):
            if value == "-":
                if used_stdin:
                    raise ValueError("stdin can be read only once")
                used_stdin = True
                lines = stdin
            else:
                lines = Path(value).read_text(encoding="utf-8").splitlines()
        else:
            lines = [value]
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            url = normalize_url(line)
            seen.add(url)
            if len(seen) > max_targets:
                raise ValueError(f"more than {max_targets} targets supplied")
    if not seen:
        raise ValueError("supply a domain, URL, or hostname/URL list")
    return sorted(seen)


class Scope:
    def __init__(self, targets, domains=(), asset_hosts=()):
        self.hosts = {urlsplit(url).hostname for url in targets}
        self.domains = {urlsplit(normalize_url(d)).hostname for d in domains}
        self.assets = {urlsplit(normalize_url(d)).hostname for d in asset_hosts}

    def allows(self, url, kind="page"):
        try:
            host = urlsplit(normalize_url(url)).hostname
        except (ValueError, UnicodeError):
            return False
        return (
            host in self.hosts
            or any(host == d or host.endswith("." + d) for d in self.domains)
            or (kind != "page" and host in self.assets)
        )
