import asyncio
import hashlib
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin

import aiohttp

from . import __version__
from .inputs import normalize_url


class PublicResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, allow_private=False):
        self.inner = aiohttp.resolver.DefaultResolver()
        self.allow_private = allow_private

    async def resolve(self, host, port=0, family=socket.AF_INET):
        records = await self.inner.resolve(host, port, family)
        if not self.allow_private and any(not public_ip(r["host"]) for r in records):
            raise OSError("non-public address blocked; use --allow-private for your lab")
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

    def metadata(self):
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "bytes": len(self.body),
            "sha256": hashlib.sha256(self.body).hexdigest() if self.body else None,
            "error": self.error,
        }


class Fetcher:
    def __init__(
        self,
        scope,
        *,
        timeout=12,
        max_bytes=4_000_000,
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
                if not self.scope.allows(current, kind):
                    raise ValueError("outside configured scope")
                from urllib.parse import urlsplit

                host = urlsplit(current).hostname
                try:
                    numeric = ipaddress.ip_address(host)
                except ValueError:
                    numeric = None
                if numeric is not None and not self.allow_private and not public_ip(host):
                    raise ValueError("non-public address blocked; use --allow-private for your lab")
                if self.total >= self.max_total:
                    raise ValueError("total download byte limit reached")
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
                        current = normalize_url(urljoin(current, location))
                        continue
                    if response.status != 200:
                        raise ValueError(f"HTTP {response.status}")
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
                        if size > self.max_bytes or self.total > self.max_total:
                            raise ValueError("download byte limit reached")
                        chunks.append(chunk)
                    result.body = b"".join(chunks)
                    return result
            raise ValueError("too many redirects")
        except (TimeoutError, ValueError, UnicodeError, OSError, aiohttp.ClientError) as exc:
            result.error = str(exc) or type(exc).__name__
            return result
