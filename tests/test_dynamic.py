import json

import pytest
from aiohttp import web

from scriptlens.dynamic import (
    MARKUP,
    available,
    describe_input,
    endpoint,
    probe_url,
    sink_findings,
)
from scriptlens.engine import Engine
from scriptlens.inputs import Scope
from scriptlens.network import Fetcher

TOKEN = "sl0123456789"


def result(sinks, parsed=False):
    return {"page": "https://app.test/", "token": TOKEN, "sinks": sinks, "parsed": parsed}


def hit(sink, value, line=6):
    return {"sink": sink, "value": value, "stack": [f"at x (https://cdn.test/app.js:{line}:9)"]}


def test_probe_url_marks_fragment_and_unused_query_names_only():
    url = probe_url("https://app.test/search?q=shoes", TOKEN)
    assert "q=shoes" in url and f"#{TOKEN}h" in url
    assert url.count("q=") == 1  # an existing parameter keeps its value
    assert "search=" + TOKEN in url


@pytest.mark.parametrize(
    "value,origin",
    [
        (TOKEN + "h", "location.hash"),
        (TOKEN + "n", "window.name"),
        (TOKEN + "q2", "query parameter 'search'"),
    ],
)
def test_marker_names_its_input(value, origin):
    assert describe_input(value, TOKEN) == origin


def test_only_a_parsed_injected_element_is_confirmed():
    value = "Results for " + TOKEN + "q0" + MARKUP
    confirmed = sink_findings(result([hit("innerHTML", value)], parsed=True))
    assert [(f["rule"], f["status"]) for f in confirmed] == [("dom_xss_runtime", "confirmed")]
    assert confirmed[0]["evidence"]["source"] == "https://cdn.test/app.js"
    assert confirmed[0]["evidence"]["line"] == 6
    inert = sink_findings(result([hit("innerHTML", value)], parsed=False))
    assert [(f["rule"], f["status"]) for f in inert] == [("dom_html_runtime", "needs_review")]


def test_encoded_or_unrelated_values_are_not_findings_worth_printing():
    encoded = sink_findings(result([hit("innerHTML", "#" + TOKEN + "h%3Cslx%20onsl=1%3E")]))
    assert [f["priority"] for f in encoded] == ["low"]
    assert sink_findings(result([hit("innerHTML", "<b>static</b>")])) == []


def test_repeated_hits_collapse():
    value = TOKEN + "h" + MARKUP
    assert len(sink_findings(result([hit("innerHTML", value)] * 5, parsed=True))) == 1


def test_runtime_endpoint_records_body_and_blocking():
    record = endpoint(
        {
            "method": "POST",
            "url": "https://app.test/api/cart?x=1",
            "type": "fetch",
            "headers": {"content-type": "application/json", "authorization": "Bearer abc"},
            "body": json.dumps({"sku": "A1", "qty": 1}),
            "blocked": True,
        },
        "https://app.test/",
    )
    assert record["body"] == {"kind": "json", "value": {"sku": "A1", "qty": 1}, "complete": True}
    assert record["execution"] == "blocked"
    assert record["query_parameters"] == [{"name": "x", "value": "1"}]
    assert "never sent" in " ".join(record["notes"])
    assert record["curl"].startswith("curl")


def test_runtime_requests_merge_into_matching_static_endpoints():
    engine = Engine(Fetcher(Scope(["https://app.test"])), source_maps=False)
    engine.process_code("fetch('/api/session')", "https://app.test/a.js", "https://app.test/")
    engine.process_code("fetch('/api/session')", "https://app.test/a.js", "https://app.test/b/")
    engine.report["endpoints"].append(
        endpoint(
            {
                "method": "GET",
                "url": "https://app.test/api/session",
                "type": "fetch",
                "headers": {},
                "body": None,
                "blocked": False,
            },
            "https://app.test/",
        )
    )
    report = engine.finalize()
    assert len(report["endpoints"]) == 1
    assert report["endpoints"][0]["observed_at_runtime"] is True
    assert report["summary"]["seen_at_runtime"] == 1


PAGE = """<!doctype html><html><body><div id=out></div><div id=safe></div><div id=h></div>
<script src="/app.js"></script></body></html>"""
APP = """
fetch('/api/session');
fetch('/api/cart', {method: 'POST', headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({sku: 'A1'})});
const p = new URLSearchParams(location.search);
if (p.get('q')) document.getElementById('out').innerHTML = 'Results for ' + p.get('q');
if (p.get('name')) document.getElementById('safe').textContent = p.get('name');
document.getElementById('h').innerHTML = location.hash;
const part = ['chunk', 'late'].join('-');
import('./' + part + '.js');
"""
CHUNK = "fetch('/api/late'); export const x = 1;"


@pytest.fixture
async def site():
    log = []

    async def handler(request):
        log.append((request.method, request.path))
        if request.path == "/":
            return web.Response(text=PAGE, content_type="text/html")
        if request.path == "/app.js":
            return web.Response(text=APP, content_type="application/javascript")
        if request.path == "/chunk-late.js":
            return web.Response(text=CHUNK, content_type="application/javascript")
        if request.path.startswith("/api/"):
            return web.json_response({})
        return web.Response(status=404)

    application = web.Application()
    application.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(application)
    await runner.setup()
    tcp = web.TCPSite(runner, "127.0.0.1", 0)
    await tcp.start()
    try:
        yield f"http://127.0.0.1:{tcp._server.sockets[0].getsockname()[1]}", log
    finally:
        await runner.cleanup()


def browser_ready():
    if not available():
        return False
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            p.chromium.launch().close()
    except Exception:
        return False
    return True


@pytest.mark.skipif(not browser_ready(), reason="Playwright with Chromium is not installed")
async def test_dynamic_scan_end_to_end(site):
    from scriptlens.dynamic import Runtime

    base, log = site
    scope = Scope([base])
    async with Fetcher(scope, allow_private=True, rate=1000) as fetcher:
        async with Runtime(scope, allow_private=True, wait=2) as runtime:
            report = await Engine(fetcher, runtime=runtime).run([base + "/"])
    assert ("POST", "/api/cart") not in log  # state-changing requests are never sent
    endpoints = {(e["method"], e["url"]): e for e in report["endpoints"]}
    assert endpoints[("POST", base + "/api/cart")]["blocked_at_runtime"] is True
    assert endpoints[("GET", base + "/api/session")]["observed_at_runtime"] is True
    assert ("GET", base + "/api/late") in endpoints  # only reachable through the runtime chunk
    printed = [f for f in report["findings"] if f["priority"] != "low"]
    confirmed = [f for f in printed if f["status"] == "confirmed"]
    assert [f["source_expression"] for f in confirmed] == ["query parameter 'q'"]
    # textContent is not a sink, and the encoded hash is low priority only
    assert not any("name" in f["title"] for f in report["findings"])
    assert report["complete"] is True
