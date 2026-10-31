"""Dynamic analysis: load supplied pages in headless Chromium and record what really happens.

* Requests the page makes by itself (fetch/XHR/beacons/WebSockets). Only GET, HEAD and OPTIONS
  are let through; anything that could change state is recorded and blocked, never sent.
* Scripts the page loads at runtime (lazy chunks, loaders), passed to the static analyzer.
* DOM sinks: a harmless marker is put in the URL fragment, a few query parameters and
  window.name. A finding is reported only when that exact marker reaches an HTML or code sink
  in the running page, so a report is an observed flow, not a guess.

Nothing is clicked or typed, no cookies or logins are used, and pages outside the scope are
not navigated to.
"""

import asyncio
import ipaddress
import json
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .inputs import third_party

INSTALL_HINT = (
    "Dynamic analysis needs Playwright and Chromium: "
    "python -m pip install 'scriptlens[dynamic]' && python -m playwright install chromium"
)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
API_TYPES = {"xhr", "fetch", "eventsource", "ping"}
# Common names pages read from the query string; added only when the URL does not have them.
PROBE_PARAMS = (
    "q",
    "query",
    "search",
    "s",
    "keyword",
    "name",
    "message",
    "error",
    "redirect",
    "next",
    "url",
    "returnUrl",
    "ref",
    "lang",
)
# Survives only if nothing encoded or sanitized it: a tag with an on* attribute.
MARKUP = "<slx onsl=1>"
KEEP_HEADERS = {"accept", "authorization", "content-type"}

HOOKS = r"""
(() => {
  if (window.__scriptlensHooked) return;
  window.__scriptlensHooked = true;
  const TOKEN = "__TOKEN__";
  if (!window.name) window.name = TOKEN + "n" + "__MARKUP__";
  const report = (sink, value) => {
    try {
      value = String(value);
      if (!value.includes(TOKEN)) return;
      const stack = (new Error().stack || "").split("\n").slice(2, 8).map(s => s.trim());
      if (window.__scriptlensSink) window.__scriptlensSink(JSON.stringify(
        {sink, value: value.slice(0, 500), stack, page: location.href}));
    } catch (e) {}
  };
  const setter = (proto, prop, sink) => {
    const d = proto && Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set) return;
    Object.defineProperty(proto, prop, {
      ...d, set(v) { report(sink, v); return d.set.call(this, v); },
    });
  };
  const method = (proto, name, sink, pick) => {
    const original = proto && proto[name];
    if (typeof original !== "function") return;
    proto[name] = function (...args) {
      report(sink, pick(args));
      return original.apply(this, args);
    };
  };
  setter(Element.prototype, "innerHTML", "innerHTML");
  setter(Element.prototype, "outerHTML", "outerHTML");
  setter(window.ShadowRoot && ShadowRoot.prototype, "innerHTML", "innerHTML");
  setter(HTMLIFrameElement.prototype, "srcdoc", "iframe.srcdoc");
  method(Element.prototype, "insertAdjacentHTML", "insertAdjacentHTML", a => a[1]);
  method(Element.prototype, "setHTMLUnsafe", "setHTMLUnsafe", a => a[0]);
  method(Document.prototype, "write", "document.write", a => a.join(""));
  method(Document.prototype, "writeln", "document.writeln", a => a.join(""));
  method(Range.prototype, "createContextualFragment", "createContextualFragment", a => a[0]);
  for (const name of ["setTimeout", "setInterval"]) {
    const original = window[name];
    window[name] = function (code, ...rest) {
      if (typeof code === "string") report(name, code);
      return original.call(this, code, ...rest);
    };
  }
})();
"""


def available():
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        return False
    return True


def blocked_host(host, allow_private):
    if allow_private or not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return not address.is_global


def probe_url(url, token):
    """The page URL plus marker values: fragment and common query names not already used."""
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    names = {k for k, _ in query}
    query += [(n, f"{token}q{i}{MARKUP}") for i, n in enumerate(PROBE_PARAMS) if n not in names]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), token + "h" + MARKUP)
    )


def describe_input(value, token):
    match = re.search(re.escape(token) + r"(h|n|q(\d+))", value)
    if not match:
        return "URL value"
    if match.group(1) == "h":
        return "location.hash"
    if match.group(1) == "n":
        return "window.name"
    return f"query parameter '{PROBE_PARAMS[int(match.group(2))]}'"


def frame_location(stack):
    """First script frame from a V8 stack line: (url, line, column)."""
    for line in stack:
        match = re.search(r"(https?://[^\s()]+):(\d+):(\d+)", line)
        if match:
            return match.group(1), int(match.group(2)), int(match.group(3))
    return None


class Runtime:
    def __init__(
        self,
        scope,
        *,
        timeout=12,
        wait=4,
        insecure=False,
        allow_private=False,
        max_bytes=16_000_000,
        concurrency=2,
    ):
        self.scope, self.timeout, self.wait = scope, timeout, wait
        self.insecure, self.allow_private = insecure, allow_private
        self.max_bytes = max_bytes
        self.limit = asyncio.Semaphore(concurrency)
        self.playwright = self.browser = None

    async def __aenter__(self):
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise ValueError(INSTALL_HINT) from exc
        self.playwright = await async_playwright().start()
        try:
            self.browser = await self.playwright.chromium.launch(headless=True)
        except Exception as exc:
            await self.playwright.stop()
            raise ValueError(
                f"could not start Chromium ({type(exc).__name__}). {INSTALL_HINT}"
            ) from exc
        return self

    async def __aexit__(self, *_):
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def observe(self, url):
        async with self.limit:
            token = "sl" + secrets.token_hex(5)
            result = {
                "page": url,
                "token": token,
                "requests": [],
                "scripts": [],
                "sinks": [],
                "parsed": False,
                "errors": [],
            }
            try:
                await self.visit(url, result, token, probe=False)
                await self.visit(probe_url(url, token), result, token, probe=True)
            except Exception as exc:  # a broken page must not stop the scan
                result["errors"].append(f"{type(exc).__name__}: {str(exc)[:300]}")
            return result

    async def visit(self, url, result, token, probe):
        context = await self.browser.new_context(
            ignore_https_errors=self.insecure, service_workers="block", accept_downloads=False
        )
        pending = []
        try:
            if probe:
                await context.add_init_script(
                    HOOKS.replace("__TOKEN__", token).replace("__MARKUP__", MARKUP)
                )

                def sink(raw):
                    try:
                        hit = json.loads(raw)
                    except ValueError:
                        return
                    if isinstance(hit, dict):
                        result["sinks"].append(hit)

                await context.expose_function("__scriptlensSink", sink)
            await context.route("**/*", lambda route: self.route(route, result, probe))
            page = await context.new_page()
            if not probe:
                page.on(
                    "response",
                    lambda response: pending.append(
                        asyncio.ensure_future(self.keep_script(response, result))
                    ),
                )
                page.on(
                    "websocket",
                    lambda ws: result["requests"].append(
                        {
                            "method": "WEBSOCKET",
                            "url": ws.url,
                            "type": "websocket",
                            "headers": {},
                            "body": None,
                            "blocked": False,
                        }
                    ),
                )
            try:
                await page.goto(url, wait_until="load", timeout=self.timeout * 2000)
            except Exception as exc:
                if not probe:
                    result["errors"].append(f"page did not load: {type(exc).__name__}")
                    return
            if not probe:
                result["final_url"] = page.url
            try:
                await page.wait_for_load_state("networkidle", timeout=self.wait * 1000)
            except Exception:
                pass  # long-polling pages never go idle; the wait above is the budget
            await page.wait_for_timeout(500)
            if probe:
                try:
                    # The strongest evidence: the marker became a real element in the page.
                    result["parsed"] = await page.evaluate(
                        "() => !!document.querySelector('slx[onsl]')"
                    )
                except Exception:
                    result["parsed"] = False
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        finally:
            await context.close()

    async def route(self, route, result, probe):
        request = route.request
        parts = urlsplit(request.url)
        if parts.scheme not in {"http", "https"}:
            return await route.continue_()
        host = parts.hostname or ""
        if blocked_host(host, self.allow_private) or third_party(host):
            return await route.abort()
        try:
            top_navigation = request.is_navigation_request() and request.frame.parent_frame is None
        except Exception:  # requests from workers have no frame
            top_navigation = False
        if top_navigation and not self.scope.allows(request.url, "page"):
            return await route.abort()
        record = not probe and request.resource_type in API_TYPES
        if request.method not in SAFE_METHODS:
            if not probe:
                result["requests"].append(self.entry(request, blocked=True))
            return await route.abort()
        if record:
            result["requests"].append(self.entry(request, blocked=False))
        await route.continue_()

    def entry(self, request, blocked):
        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() in KEEP_HEADERS
            or (k.lower().startswith("x-") and k.lower() != "x-client-data")
        }
        body = request.post_data
        return {
            "method": request.method,
            "url": request.url,
            "type": request.resource_type,
            "headers": headers,
            "body": body[:20_000] if isinstance(body, str) else None,
            "blocked": blocked,
        }

    async def keep_script(self, response, result):
        request = response.request
        if request.resource_type != "script" or response.status != 200:
            return
        if not self.scope.allows(response.url, "script"):
            return
        try:
            body = await response.body()
        except Exception:
            return
        if len(body) <= self.max_bytes:
            result["scripts"].append((response.url, body))


HTML_SINKS = {
    "innerHTML",
    "outerHTML",
    "iframe.srcdoc",
    "insertAdjacentHTML",
    "setHTMLUnsafe",
    "document.write",
    "document.writeln",
    "createContextualFragment",
}


def sink_findings(result):
    """Findings for marker values that reached sinks; duplicates collapse to one."""
    findings, seen = [], set()
    token = result["token"]
    for hit in result["sinks"]:
        sink, value = str(hit.get("sink", "")), str(hit.get("value", ""))
        if token not in value:
            continue
        origin = describe_input(value, token)
        where = frame_location(hit.get("stack") or []) or (result["page"], 0, 0)
        intact = MARKUP in value
        if sink in HTML_SINKS and intact and result.get("parsed"):
            rule, priority, status = "dom_xss_runtime", "high", "confirmed"
            title = f"{origin} reaches {sink} unescaped; injected element present in the page"
            check = (
                "Observed in Chromium: the marker tag with an on* attribute became a DOM "
                "element. Confirm impact with a benign payload on an authorized target."
            )
        elif sink in HTML_SINKS and intact:
            rule, priority, status = "dom_html_runtime", "high", "needs_review"
            title = f"{origin} reaches {sink} unescaped"
            check = (
                "Observed in Chromium: markup reached the sink without encoding but was not "
                "found as an element afterwards (it may be inert or removed). Review the context."
            )
        elif sink in HTML_SINKS:
            rule, priority, status = "dom_flow_runtime", "low", "encoded"
            title = f"{origin} reaches {sink}; special characters were encoded"
            check = "Encoded before the sink in this run; usually not exploitable."
        else:
            rule, priority, status = "code_flow_runtime", "high", "needs_review"
            title = f"{origin} reaches {sink} as code"
            check = "Observed in Chromium: a URL value became code. Review quoting and impact."
        key = (rule, sink, origin, where)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "rule": rule,
                "title": title,
                "priority": priority,
                "status": status,
                "check": check,
                "evidence": {
                    "source": where[0],
                    "line": where[1],
                    "column": where[2],
                    "snippet": value[:300],
                    "page": hit.get("page") or result["page"],
                },
                "source_expression": origin,
                "sink": sink,
                "observed": "runtime",
            }
        )
    return findings


def endpoint(request, page):
    """An endpoint record (same shape as static ones) for a request the page really made."""
    from .requests import curl_example, review_checks

    method, url = request["method"], request["url"]
    headers = dict(request["headers"])
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    raw = request["body"]
    if raw is None:
        body = {"kind": "none", "value": None, "complete": True}
    elif "json" in content_type:
        try:
            body = {"kind": "json", "value": json.loads(raw), "complete": True}
        except ValueError:
            body = {"kind": "raw", "value": raw[:2000], "complete": len(raw) <= 2000}
    elif "x-www-form-urlencoded" in content_type:
        body = {
            "kind": "urlencoded",
            "value": dict(parse_qsl(raw, keep_blank_values=True)),
            "complete": True,
        }
    elif "multipart" in content_type:
        body = {"kind": "multipart", "value": None, "complete": False}
    else:
        body = {"kind": "raw", "value": raw[:2000], "complete": len(raw) <= 2000}
    notes = ["Observed in a headless browser without cookies or login"]
    if request["blocked"]:
        notes.append("State-changing request: recorded and blocked by ScriptLens, never sent")
    record = {
        "method": method,
        "url": url,
        "url_template": url,
        "library": "browser",
        "headers": headers,
        "body": body,
        "query_parameters": [
            {"name": k, "value": v}
            for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        ],
        "credentials_mode": "browser default",
        "evidence": [
            {
                "source": "runtime",
                "page": page,
                "line": 0,
                "column": 0,
                "snippet": f"{method} {url}"[:500],
            }
        ],
        "notes": notes,
        "suggested_checks": review_checks(urlsplit(url).path, method),
        "execution": "blocked" if request["blocked"] else "observed",
        "observed_at_runtime": True,
    }
    record["curl"] = None if method in {"WEBSOCKET", "SSE"} else curl_example(record)
    return record
