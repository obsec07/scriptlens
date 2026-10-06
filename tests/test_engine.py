import base64
import json

import pytest
from aiohttp import web

from scriptlens.engine import Engine
from scriptlens.inputs import Scope
from scriptlens.network import Fetcher, Response


@pytest.fixture
async def lab():
    seen = []
    application = web.Application()

    async def handler(request):
        seen.append((request.method, request.path, request.headers.get("Cookie")))
        if request.path == "/":
            return web.Response(
                text="""<html><base href="/app/"><script src="/bundle.js"></script><script src="/bundle.js"></script><script>fetch('/inline')</script><script type="application/json">{"path":"/not-an-endpoint"}</script><a href="/next">next</a></html>""",
                content_type="text/html",
                headers={"Set-Cookie": "secret=do-not-reuse"},
            )
        if request.path == "/bundle.js":
            return web.Response(
                text="""import './chunk.js'; fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:user.name})}); fetch('relative'); //# sourceMappingURL=bundle.js.map""",
                content_type="application/javascript",
            )
        if request.path == "/chunk.js":
            return web.Response(
                text="axios.delete('/api/users/1')", content_type="application/javascript"
            )
        if request.path == "/bundle.js.map":
            return web.json_response(
                {
                    "version": 3,
                    "sources": ["../../original.ts", "https://evil.test/must-not-fetch.js"],
                    "sourcesContent": [
                        "const x: string='/mapped'; fetch(x)",
                        "import './never-fetch.js'; fetch('/from-map')",
                    ],
                }
            )
        if request.path == "/next":
            return web.Response(text="<html>no scripts</html>", content_type="text/html")
        if request.path == "/redirect":
            raise web.HTTPFound("http://localhost:" + str(request.url.port) + "/forbidden")
        if request.path == "/large.js":
            return web.Response(body=b"x" * 10000, content_type="application/javascript")
        if request.path == "/compressed.js":
            return web.Response(body=b"not-really-gzip", headers={"Content-Encoding": "gzip"})
        if request.path == "/html.js":
            return web.Response(text="<html>login required</html>", content_type="text/html")
        return web.Response(status=404)

    application.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(application)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}", seen
    finally:
        await runner.cleanup()


async def test_full_discovery_never_executes_extracted_endpoints_or_map_filenames(lab):
    base, seen = lab
    fetcher = Fetcher(Scope([base]), allow_private=True, rate=1000)
    async with fetcher:
        report = await Engine(fetcher).run([base + "/"])
    paths = [path for _, path, _ in seen]
    assert all(method == "GET" for method, _, _ in seen)
    assert all(cookie is None for _, _, cookie in seen)
    assert paths.count("/bundle.js") == 1
    assert "/api/users" not in paths
    assert "/never-fetch.js" not in paths
    assert "/forbidden" not in paths
    assert set(paths) == {"/", "/bundle.js", "/chunk.js", "/bundle.js.map", "/next"}
    endpoints = {item["url"]: item for item in report["endpoints"]}
    assert base + "/app/relative" in endpoints
    assert base + "/mapped" in endpoints
    assert endpoints[base + "/api/users"]["method"] == "POST"
    assert report["complete"] is True


async def test_out_of_scope_redirect_is_blocked_before_second_request(lab):
    base, seen = lab
    async with Fetcher(Scope([base]), allow_private=True, rate=1000) as fetcher:
        response = await fetcher.get(base + "/redirect", "page")
    assert response.error == "outside configured scope"
    assert [path for _, path, _ in seen] == ["/redirect"]


async def test_default_private_target_is_blocked(lab):
    base, seen = lab
    async with Fetcher(Scope([base]), rate=1000) as fetcher:
        response = await fetcher.get(base + "/")
    assert "non-public address blocked" in response.error
    assert seen == []


@pytest.mark.parametrize(
    "path,reason",
    [
        ("/large.js", "byte limit"),
        ("/compressed.js", "compressed body"),
        ("/html.js", "received HTML"),
    ],
)
async def test_incomplete_downloads_stay_in_json_without_fake_endpoints(lab, path, reason):
    base, _ = lab
    fetcher = Fetcher(Scope([base]), allow_private=True, rate=1000, max_bytes=1000)
    async with fetcher:
        report = await Engine(fetcher).run([base + path])
    assert report["endpoints"] == []
    assert report["complete"] is False
    assert reason in json.dumps(report["diagnostics"])


def test_inline_map_parses_embedded_sources_without_writing_source_paths():
    engine = Engine(Fetcher(Scope(["https://example.test"])))
    raw = json.dumps(
        {
            "version": 3,
            "sources": ["../../../../tmp/must-not-write.js"],
            "sourcesContent": ["fetch('/mapped')"],
        }
    ).encode()
    engine.inline_map(
        "data:application/json;base64," + base64.b64encode(raw).decode(),
        "https://example.test/app.js",
        "https://example.test/",
    )
    report = engine.finalize()
    assert report["endpoints"][0]["url"] == "https://example.test/mapped"
    assert not engine.queue


def test_dedup_preserves_independent_request_shapes_and_source_locations():
    engine = Engine(Fetcher(Scope([])), source_maps=False)
    engine.process_code(
        "fetch('/api');fetch('/api');fetch('/api',{method:'POST'})",
        "file.js",
        "https://example.test",
        discover=False,
    )
    result = engine.finalize()["endpoints"]
    assert len(result) == 2
    assert len(next(r for r in result if r["method"] == "GET")["evidence"]) == 2


def test_small_password_and_auth_are_redacted_from_final_curl_and_evidence():
    engine = Engine(Fetcher(Scope([])), source_maps=False)
    engine.process_code(
        "fetch('/api',{method:'POST',headers:{Authorization:'abc123'},body:JSON.stringify({password:'a'})})",
        "file.js",
        "https://example.test",
        discover=False,
    )
    report = engine.finalize()
    assert report["endpoints"][0]["body"]["value"]["password"] == "{{REDACTED}}"
    assert "abc123" not in json.dumps(report)
    assert '"password":"a"' not in report["endpoints"][0]["curl"]
    assert "password:'a'" not in report["endpoints"][0]["evidence"][0]["snippet"]


def test_sensitive_query_values_are_redacted_in_structured_parameters():
    engine = Engine(Fetcher(Scope([])), source_maps=False)
    engine.process_code(
        "fetch('/api?token=sensitive-query-value')",
        "file.js",
        "https://example.test",
        discover=False,
    )
    report = engine.finalize()
    assert "sensitive-query-value" not in json.dumps(report)


async def test_limits_produce_partial_report(lab):
    base, _ = lab
    async with Fetcher(Scope([base]), allow_private=True, rate=1000) as fetcher:
        report = await Engine(fetcher, max_files=1).run([base + "/"])
    assert report["complete"] is False
    assert "file limit reached" in json.dumps(report["diagnostics"])


async def test_same_script_keeps_different_page_resolution_contexts():
    class FakeFetcher:
        scope = Scope(["https://app.test"])
        concurrency = 3
        max_bytes = 1_000_000

        async def get(self, url, kind):
            if kind == "page":
                return Response(
                    url,
                    url,
                    200,
                    b'<script src="/same.js"></script>',
                    {"content-type": "text/html"},
                )
            return Response(
                url, url, 200, b"fetch('relative')", {"content-type": "text/javascript"}
            )

    report = await Engine(FakeFetcher()).run(["https://app.test/a/", "https://app.test/b/"])
    assert {e["url"] for e in report["endpoints"]} == {
        "https://app.test/a/relative",
        "https://app.test/b/relative",
    }
