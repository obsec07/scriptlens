import ipaddress
import re
from contextlib import nullcontext
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


MAX_TARGETS = 100_000


def load_targets(values, lists, stdin, max_targets=MAX_TARGETS, limit=None):
    if limit is not None and not 1 <= limit <= max_targets:
        raise ValueError(f"target count must be between 1 and {max_targets:,}")
    seen = dict()
    used_stdin = False
    for value, is_file in [(v, False) for v in values] + [(v, True) for v in lists]:
        if "://" not in value and value != "-":
            path = Path(value)
            if path.is_dir():
                raise ValueError(f"expected a domain/URL list file, got a directory: {value}")
            if not path.is_file() and (
                value.startswith(("/", "./", "../", "~"))
                or path.suffix.lower() in {".txt", ".list", ".lst"}
            ):
                raise ValueError(f"input list file does not exist: {value}")
        if is_file or value == "-" or ("://" not in value and Path(value).is_file()):
            if value == "-":
                if used_stdin:
                    raise ValueError("stdin can be read only once")
                used_stdin = True
                source = nullcontext(stdin)
            else:
                source = Path(value).open(encoding="utf-8-sig")
        else:
            source = nullcontext([value])
        with source as lines:
            for line in lines:
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                url = normalize_url(line)
                seen[url] = None
                if len(seen) > max_targets:
                    raise ValueError(
                        f"more than {max_targets:,} targets supplied; "
                        "select a subset with --number-of-domains"
                    )
                if limit is not None and len(seen) == limit:
                    return list(seen)
    if not seen:
        raise ValueError("supply a domain, URL, or hostname/URL list")
    return list(seen)


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
