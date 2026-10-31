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


# Analytics, advertising, consent, chat and public-library CDNs. Their scripts are the same on
# every site, so analyzing them only adds endpoints and clues that are not the target's.
THIRD_PARTY = (
    "googletagmanager.com",
    "google-analytics.com",
    "googleadservices.com",
    "googlesyndication.com",
    "doubleclick.net",
    "gstatic.com",
    "google.com",
    "recaptcha.net",
    "hcaptcha.com",
    "apis.google.com",
    "maps.googleapis.com",
    "ajax.googleapis.com",
    "facebook.net",
    "facebook.com",
    "analytics.tiktok.com",
    "hotjar.com",
    "intercom.io",
    "intercomcdn.com",
    "segment.com",
    "segment.io",
    "mxpnl.com",
    "amplitude.com",
    "js.stripe.com",
    "hs-scripts.com",
    "hs-analytics.net",
    "hsforms.net",
    "hubspot.com",
    "cookielaw.org",
    "onetrust.com",
    "cookiebot.com",
    "cloudflareinsights.com",
    "challenges.cloudflare.com",
    "sentry-cdn.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "code.jquery.com",
    "twitter.com",
    "twimg.com",
    "ads-twitter.com",
    "licdn.com",
    "linkedin.com",
    "bing.com",
    "clarity.ms",
    "newrelic.com",
    "nr-data.net",
    "datadoghq-browser-agent.com",
    "fullstory.com",
    "optimizely.com",
    "youtube.com",
    "vimeo.com",
    "vimeocdn.com",
    "onesignal.com",
    "zdassets.com",
    "zendesk.com",
    "livechatinc.com",
    "crisp.chat",
    "tawk.to",
    "drift.com",
    "driftt.com",
    "wistia.com",
    "wistia.net",
    "branch.io",
    "heapanalytics.com",
    "posthog.com",
    "plausible.io",
    "mouseflow.com",
    "quantserve.com",
    "scorecardresearch.com",
    "adsrvr.org",
    "criteo.com",
    "criteo.net",
    "taboola.com",
    "outbrain.com",
    "pinimg.com",
    "redditstatic.com",
    "appleid.cdn-apple.com",
    "accounts.google.com",
    "hs-banner.com",
    "usercentrics.eu",
    "trustarc.com",
    "qualtrics.com",
    "mktoresp.com",
    "marketo.net",
    "pardot.com",
    "adroll.com",
    "yandex.ru",
    "mc.yandex.ru",
    "snapchat.com",
    "sc-static.net",
)


def third_party(host):
    return any(host == d or host.endswith("." + d) for d in THIRD_PARTY)


class Scope:
    """Pages: the supplied hosts (plus --scope domains). Scripts and maps referenced by those
    pages: any public host by default, like a browser loads them, except well-known third-party
    services. strict=True limits scripts/maps to the supplied hosts and --asset-host as well."""

    def __init__(self, targets, domains=(), asset_hosts=(), strict=False):
        self.hosts = {urlsplit(url).hostname for url in targets}
        self.domains = {urlsplit(normalize_url(d)).hostname for d in domains}
        self.assets = {urlsplit(normalize_url(d)).hostname for d in asset_hosts}
        self.strict = strict

    def in_scope(self, host):
        return host in self.hosts or any(host == d or host.endswith("." + d) for d in self.domains)

    def allows(self, url, kind="page"):
        try:
            host = urlsplit(normalize_url(url)).hostname
        except (ValueError, UnicodeError):
            return False
        if self.in_scope(host):
            return True
        if kind == "page":
            return False
        if host in self.assets:
            return True
        return not self.strict and not third_party(host)

    def follow(self, current, target, kind):
        """A page's redirect between example.com and www.example.com (either way) keeps the site
        in scope; the new host is then treated as supplied."""
        old, new = urlsplit(current).hostname, urlsplit(target).hostname
        if (
            kind == "page"
            and old in self.hosts
            and new
            and (new == "www." + old or old == "www." + new)
        ):
            self.hosts.add(new)
            return True
        return False
