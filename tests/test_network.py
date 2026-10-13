import socket
import ssl
from types import SimpleNamespace

import aiohttp
import pytest

from scriptlens.inputs import Scope
from scriptlens.network import Fetcher, PrivateAddressError, PublicResolver


@pytest.mark.parametrize("blocked", [False, True])
async def test_dns_and_private_address_errors_survive_connector_wrapping(monkeypatch, blocked):
    async def fail(*args, **kwargs):
        if blocked:
            raise PrivateAddressError("non-public address blocked")
        raise socket.gaierror(socket.EAI_NONAME, "synthetic DNS failure")

    monkeypatch.setattr(PublicResolver, "resolve", fail)
    async with Fetcher(Scope(["https://example.test"])) as fetcher:
        response = await fetcher.get("https://example.test/app.js")
    assert response.error_code == ("private_address" if blocked else "dns")
    assert response.body == b""
    assert response.hint


@pytest.mark.parametrize(
    "error_type,code",
    [
        ("certificate", "tls_certificate"),
        ("tls", "tls_handshake"),
        ("refused", "connection"),
        ("payload", "response_body"),
    ],
)
async def test_transport_exceptions_have_distinct_codes(error_type, code):
    key = SimpleNamespace(host="example.test", port=443, ssl=True, is_ssl=True)
    errors = {
        "certificate": aiohttp.ClientConnectorCertificateError(
            key, ssl.CertificateError("synthetic invalid certificate")
        ),
        "tls": aiohttp.ClientConnectorSSLError(key, ssl.SSLError("synthetic handshake failure")),
        "refused": aiohttp.ClientConnectorError(key, ConnectionRefusedError(111, "refused")),
        "payload": aiohttp.ClientPayloadError("synthetic truncated response"),
    }

    def fail(*args, **kwargs):
        raise errors[error_type]

    fetcher = Fetcher(Scope(["https://example.test"]))
    fetcher.session = SimpleNamespace(get=fail)
    response = await fetcher.get("https://example.test/app.js")
    assert response.error_code == code
    assert response.hint
    assert response.body == b""
    assert response.final_url == "https://example.test/app.js"
