import asyncio
import hashlib
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin

import aiohttp

from . import __version__
from .inputs import normalize_url

DEFAULT_MAX_BYTES = 16_000_000


class FetchError(ValueError):
    def __init__(self, code, reason, hint):
        super().__init__(reason)
        self.code, self.hint = code, hint


class PrivateAddressError(OSError):
    pass


def explain_error(exc, timeout):
    """Keep transport failures distinct from HTTP responses and collection limits."""
    if isinstance(exc, FetchError):
        return exc.code, str(exc), exc.hint
    underlying = getattr(exc, "os_error", exc)
    if isinstance(underlying, PrivateAddressError):
        return "private_address", str(underlying), "Use --allow-private only for your lab."
    if isinstance(exc, aiohttp.ClientConnectorCertificateError):
        return (
            "tls_certificate",
            "TLS certificate verification failed",
            "Check the server certificate and local CA trust; -k skips verification if intended.",
        )
    if isinstance(exc, (aiohttp.ClientSSLError,)):
        return "tls_handshake", "TLS handshake failed", "Check the URL scheme and server TLS setup."
    if isinstance(exc, (socket.gaierror, aiohttp.ClientConnectorDNSError)):
        return "dns", "DNS lookup failed", "Check the hostname, DNS resolver and VPN connection."
    if isinstance(exc, TimeoutError):
        return (
            "timeout",
            f"request timed out (budget: {timeout:g}s)",
            "Check connectivity or increase --timeout (for example, --timeout 30).",
        )
    if isinstance(exc, aiohttp.ClientPayloadError):
        return "response_body", "response body was interrupted or invalid", "Retry the source URL."
    if isinstance(exc, (aiohttp.ClientConnectionError, OSError)):
        return (
            "connection",
            "connection failed: " + (str(underlying) or type(exc).__name__),
            "Check the host, port, network and VPN; ScriptLens does not use environment proxies.",
        )
    return "fetch", str(exc) or type(exc).__name__, ""


class PublicResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, allow_private=False):
        self.inner = aiohttp.resolver.DefaultResolver()
        self.allow_private = allow_private

    async def resolve(self, host, port=0, family=socket.AF_INET):
        records = await self.inner.resolve(host, port, family)
        if not self.allow_private and any(not public_ip(r["host"]) for r in records):
            raise PrivateAddressError(
                "non-public address blocked; use --allow-private for your lab"
            )
        return records

    async def close(self):
        await self.inner.close()


def public_ip(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


@dataclass
class Response:
    url: str
    final_url: str = ""
    status: int | None = None
    body: bytes = b""
    headers: dict = field(default_factory=dict)
    error: str | None = None
    error_code: str | None = None
    hint: str | None = None

    def metadata(self):
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "bytes": len(self.body),
            "sha256": hashlib.sha256(self.body).hexdigest() if self.body else None,
            "error": self.error,
            "error_code": self.error_code,
            "hint": self.hint,
        }


class Fetcher:
    def __init__(
        self,
        scope,
        *,
        timeout=12,
        max_bytes=DEFAULT_MAX_BYTES,
        max_total=80_000_000,
        concurrency=6,
        rate=8,
        insecure=False,
        allow_private=False,
    ):
        self.scope, self.timeout = scope, timeout
        self.max_bytes, self.max_total = max_bytes, max_total
        self.concurrency, self.rate = concurrency, rate
        self.insecure, self.allow_private = insecure, allow_private
        self.total = 0
        self.lock = asyncio.Lock()
        self.last_start = 0.0

    async def __aenter__(self):
        self.resolver = PublicResolver(self.allow_private)
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                resolver=self.resolver, limit=self.concurrency, use_dns_cache=False
            ),
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            cookie_jar=aiohttp.DummyCookieJar(),
            trust_env=False,
            auto_decompress=False,
            headers={"User-Agent": f"ScriptLens/{__version__}", "Accept-Encoding": "identity"},
        )
        return self

    async def __aexit__(self, *_):
        await self.session.close()
        await self.resolver.close()

    async def get(self, url, kind="script"):
        result = Response(url)
        try:
            current = normalize_url(url)
            for _ in range(6):
                result.final_url, result.status = current, None
                if not self.scope.allows(current, kind):
                    raise ValueError("outside configured scope")
                from urllib.parse import urlsplit

                host = urlsplit(current).hostname
                try:
                    numeric = ipaddress.ip_address(host)
                except ValueError:
                    numeric = None
                if numeric is not None and not self.allow_private and not public_ip(host):
                    raise PrivateAddressError(
                        "non-public address blocked; use --allow-private for your lab"
                    )
                if self.total >= self.max_total:
                    raise self.total_limit_error()
                async with self.lock:
                    loop = asyncio.get_running_loop()
                    await asyncio.sleep(max(0, self.last_start + 1 / self.rate - loop.time()))
                    self.last_start = loop.time()
                async with self.session.get(
                    current, allow_redirects=False, ssl=False if self.insecure else True
                ) as response:
                    result.final_url, result.status = current, response.status
                    result.headers = {
                        k.lower(): v
                        for k, v in response.headers.items()
                        if k.lower() in {"content-type", "sourcemap", "x-sourcemap", "location"}
                    }
                    if response.status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("Location")
                        if not location:
                            raise ValueError("redirect has no destination")
                        target = normalize_url(urljoin(current, location))
                        self.scope.follow(current, target, kind)
                        current = target
                        continue
                    if response.status != 200:
                        raise FetchError(
                            "http_status",
                            f"HTTP {response.status}",
                            "The server responded; check the URL and whether access is restricted.",
                        )
                    if response.headers.get("Content-Encoding", "identity").lower() not in {
                        "",
                        "identity",
                    }:
                        raise ValueError(
                            "server ignored identity encoding; compressed body skipped"
                        )
                    chunks, size = [], 0
                    async for chunk in response.content.iter_chunked(65536):
                        size += len(chunk)
                        self.total += len(chunk)
                        if self.total > self.max_total:
                            raise self.total_limit_error()
                        if size > self.max_bytes:
                            raise FetchError(
                                "file_byte_limit",
                                f"file download byte limit reached ({self.max_bytes:,} bytes)",
                                "Increase --max-bytes for this bundle "
                                f"(for example, --max-bytes {self.max_bytes * 2}).",
                            )
                        chunks.append(chunk)
                    result.body = b"".join(chunks)
                    return result
            raise ValueError("too many redirects")
        except (TimeoutError, ValueError, UnicodeError, OSError, aiohttp.ClientError) as exc:
            result.error_code, result.error, result.hint = explain_error(exc, self.timeout)
            return result

    def total_limit_error(self):
        return FetchError(
            "total_byte_limit",
            f"total download byte limit reached ({self.max_total:,} bytes)",
            "Increase --max-total-bytes or scan fewer inputs at a time.",
        )
