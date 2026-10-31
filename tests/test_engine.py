import asyncio
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
        if request.path == "/bundle-over-4mb.js":
            return web.Response(
                body=b"/*" + b"x" * 4_100_000 + b"*/fetch('/large-bundle-api')",
                content_type="application/javascript",
            )
        if request.path == "/slow.js":
            await asyncio.sleep(0.1)
            return web.Response(text="fetch('/slow')", content_type="application/javascript")
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


async def test_bundle_above_old_limit_is_analyzed_with_new_defaults(lab):
    base, _ = lab
    async with Fetcher(Scope([base]), allow_private=True, rate=1000) as fetcher:
        report = await Engine(fetcher, base_url=base).run([base + "/bundle-over-4mb.js"])
    assert report["complete"]
    assert report["summary"]["analyzed_sources"] == 1
    assert report["endpoints"][0]["url"] == base + "/large-bundle-api"
    assert report["endpoints"][0]["evidence"][0]["column"] == 4_100_005


@pytest.mark.parametrize(
    "options,code,flag",
    [
        ({"max_bytes": 1000}, "file_byte_limit", "--max-bytes"),
        ({"max_total": 1000}, "total_byte_limit", "--max-total-bytes"),
    ],
)
async def test_download_limits_have_distinct_actionable_diagnostics(lab, options, code, flag):
    base, _ = lab
    async with Fetcher(Scope([base]), allow_private=True, rate=1000, **options) as fetcher:
        report = await Engine(fetcher).run([base + "/large.js"])
    assert not report["complete"]
    assert not report["endpoints"]
    diagnostic = report["diagnostics"][0]
    assert diagnostic["code"] == code
    assert flag in diagnostic["hint"]
    assert report["sources"][0]["error_code"] == code
    assert "1,000" in diagnostic["reason"]


async def test_timeout_is_saved_with_useful_reason(lab):
    base, _ = lab
    async with Fetcher(Scope([base]), allow_private=True, timeout=0.01) as fetcher:
        report = await Engine(fetcher).run([base + "/slow.js"])
    assert report["diagnostics"][0]["code"] == "timeout"
    assert "--timeout" in report["diagnostics"][0]["hint"]
    assert report["sources"][0]["final_url"] == base + "/slow.js"


async def test_http_error_is_not_reported_as_connection_failure(lab):
    base, _ = lab
    async with Fetcher(Scope([base]), allow_private=True) as fetcher:
        response = await fetcher.get(base + "/missing.js")
    assert response.status == 404
    assert response.error == "HTTP 404"
    assert response.error_code == "http_status"


async def test_bulk_scan_reaches_later_inputs_with_fresh_page_file_and_byte_budgets():
    targets = [f"https://host{i}.example.test/" for i in range(1001)]
    visited = []

    class BulkFetcher:
        scope = Scope(targets)
        concurrency = 2
        max_bytes = 1000
        max_total = 100
        total = 0

        async def get(self, url, kind):
            assert self.total < self.max_total, "earlier inputs exhausted the download budget"
            self.total += 40
            visited.append(url)
            if kind == "page":
                return Response(
                    url, url, 200, b'<script src="/app.js"></script>', {"content-type": "text/html"}
                )
            return Response(url, url, 200, b"fetch('/api')", {"content-type": "text/javascript"})

    fetcher = BulkFetcher()
    engine = Engine(fetcher, max_pages=1, max_files=1)
    report = await engine.run(targets)
    assert report["complete"]
    assert set(targets).issubset(visited)
    assert len(visited) == 2002
    assert len(report["endpoints"]) == 1001
    assert report["summary"]["analyzed_sources"] == 1001
    assert not engine.cache
    assert fetcher.max_total == 100


async def test_download_cache_does_not_retain_every_source():
    class SmallFetcher:
        scope = Scope(["https://example.test"])
        concurrency = 6

        async def get(self, url, kind):
            return Response(url, url, 200, b"fetch('/api')")

    engine = Engine(SmallFetcher())
    for i in range(200):
        await engine.cached_get(f"https://example.test/{i}.js", "script")
    assert len(engine.cache) <= 128


async def test_report_limit_in_early_batch_does_not_discard_later_target_results():
    targets = ["https://first.test/app.js", "https://last.test/app.js"]

    class LimitedFetcher:
        scope = Scope(targets)
        concurrency = 1
        max_bytes = 1000

        async def get(self, url, kind):
            body = f"fetch('{url}/one');fetch('{url}/two')".encode()
            return Response(url, url, 200, body, {"content-type": "text/javascript"})

    report = await Engine(LimitedFetcher(), max_report_items=1).run(targets)
    assert {item["url"] for item in report["endpoints"]} == {t + "/one" for t in targets}
    assert not report["complete"]
    assert report["summary"]["incomplete"] == 2


async def test_extra_links_third_party_scripts_and_small_parse_gaps_are_not_failures():
    class FakeFetcher:
        scope = Scope(["https://app.test"])
        concurrency = 3
        max_bytes = 1_000_000

        async def get(self, url, kind):
            if kind == "page":
                links = "".join(f'<a href="/p{i}">p</a>' for i in range(30))
                return Response(
                    url,
                    url,
                    200,
                    (
                        '<script src="https://cdn.app-assets.test/app.js"></script>'
                        '<script src="https://www.googletagmanager.com/gtm.js"></script>' + links
                    ).encode(),
                    {"content-type": "text/html"},
                )
            # one unparsable construct inside an otherwise fine, large bundle
            code = "fetch('/api/a');" + "var x=1;" * 2000 + "a = String.raw`\\\\u{zz`; ]]] ;"
            return Response(url, url, 200, code.encode(), {"content-type": "text/javascript"})

    report = await Engine(FakeFetcher(), max_pages=2).run(["https://app.test/"])
    reasons = json.dumps(report["diagnostics"])
    assert "third-party service script" in reasons
    assert "linked page(s) not crawled" in reasons
    assert "small syntax region" in reasons
    assert report["complete"] is True
    assert {e["url"] for e in report["endpoints"]} == {"https://app.test/api/a"}
    assert report["summary"]["downloads"] >= 3


def test_badly_broken_source_is_still_incomplete():
    engine = Engine(Fetcher(Scope([])), source_maps=False)
    engine.process_code("function broken( { fetch('/x'", "app.js")
    report = engine.finalize()
    assert report["complete"] is False
