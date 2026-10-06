import io

import pytest

from scriptlens.inputs import Scope, load_targets, normalize_url
from scriptlens.network import public_ip


def test_lists_domains_urls_and_duplicates(tmp_path):
    path = tmp_path / "hosts.txt"
    path.write_text(
        "example.test\nhttps://example.test/#fragment\n# comment\nhttps://other.test/app\n"
    )
    assert load_targets(["example.test", str(path)], [], io.StringIO()) == [
        "https://example.test/",
        "https://other.test/app",
    ]


@pytest.mark.parametrize(
    "value",
    [
        "file:///etc/passwd",
        "https://user:pass@example.test",
        "https://foo\\@example.test",
        "https://example.test/\x1b[31m",
        "https://exa mple.test",
        "https://-bad.test",
    ],
)
def test_invalid_input(value):
    with pytest.raises(ValueError):
        normalize_url(value)


def test_scope_does_not_leak_to_suffix_lookalike_or_cdn_pages():
    scope = Scope(["https://app.example.test/"], ["example.org"], ["cdn.example.net"])
    assert scope.allows("https://sub.example.org/a.js", "script")
    assert not scope.allows("https://example.org.evil.test/a.js", "script")
    assert scope.allows("https://cdn.example.net/a.js", "script")
    assert not scope.allows("https://cdn.example.net/page", "page")


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "224.0.0.1"]
)
def test_private_multicast_and_metadata_addresses_are_not_public(address):
    assert not public_ip(address)
