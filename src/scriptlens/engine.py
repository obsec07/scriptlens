import asyncio
import base64
import hashlib
import json
from collections import deque
from datetime import UTC, datetime
from urllib.parse import unquote_to_bytes, urljoin, urlsplit

from . import __version__
from .analyzer import analyze
from .discovery import Page
from .inputs import normalize_url, third_party
from .requests import curl_example
from .security import Redactor


class Engine:
    def __init__(
        self,
        fetcher,
        *,
        max_files=100,
        max_pages=10,
        depth=1,
        source_maps=True,
        base_url=None,
        max_nodes=250_000,
        max_report_items=25_000,
        runtime=None,
    ):
        self.fetcher, self.scope = fetcher, fetcher.scope
        self.max_files, self.max_pages, self.depth = max_files, max_pages, depth
        self.source_maps, self.base_url = source_maps, base_url
        self.max_nodes = max_nodes
        self.max_report_items = max_report_items
        self.report_item_offset = 0
        self.runtime = runtime
        self.fetched = set()
        self.redactor = Redactor()
        self.report = {
            "schema_version": 1,
            "tool": "ScriptLens",
            "version": __version__,
            "started_at": datetime.now(UTC).isoformat(),
            "targets": [],
            "endpoints": [],
            "findings": [],
            "graphql_operations": [],
            "unresolved_requests": [],
            "sources": [],
            "runtime": [],
            "diagnostics": [],
            "limitations": [
                "Static analysis; no JavaScript, extracted API request or curl example "
                "is executed.",
                "Runtime chunks, authentication-only code, imported values and complex "
                "data flow may be missed.",
                "Request templates do not include browser cookies or prove server behavior.",
                "Security clues need manual validation; priority is review order, "
                "not proven severity.",
            ],
        }
        self.queue, self.seen, self.cache = deque(), set(), {}
        if runtime is not None:
            self.report["limitations"][0] = (
                "Static analysis plus a headless-browser load of each supplied page (--dynamic). "
                "Extracted requests and curl examples are never sent; in the browser only the "
                "page's own GET/HEAD/OPTIONS requests run, other methods are recorded and blocked."
            )
        self.pages = self.files = self.analyzed = 0
        self.analysis_attempts = 0
        self.downloads = 0
        self.links_not_crawled = 0

    def diagnostic(self, url, reason, category="incomplete", *, code=None, hint=None):
        item = {"source": url, "category": category, "reason": reason}
        if code:
            item["code"] = code
        if hint:
            item["hint"] = hint
        self.report["diagnostics"].append(item)

    def enqueue(self, url, kind, document=None, depth=0):
        try:
            url = normalize_url(url)
        except (ValueError, UnicodeError) as exc:
            self.diagnostic(str(url)[:500], str(exc), "skipped")
            return
        key = (url, kind, document)
        if key in self.seen:
            return
        self.seen.add(key)
        if not self.scope.allows(url, kind):
            host = urlsplit(url).hostname or ""
            if kind != "page" and third_party(host):
                reason = "third-party service script (analytics, ads, consent or public CDN)"
            elif kind == "page":
                reason = "page outside scope; add --scope to crawl it"
            else:
                reason = "outside scope; add an authorized --asset-host or --scope"
            self.diagnostic(url, reason, "skipped")
            return
        if len(self.queue) >= (self.max_files + self.max_pages) * 4:
            if not any(
                d["reason"] == "discovery queue limit reached" for d in self.report["diagnostics"]
            ):
                self.diagnostic(url, "discovery queue limit reached")
            return
        self.queue.append((url, kind, document, depth))

    def process_code(self, code, source, document=None, line_offset=0, discover=True):
        if self.analysis_attempts >= self.max_files * 4:
            self.diagnostic(source, "analysis unit limit reached")
            return
        self.analysis_attempts += 1
        try:
            result = analyze(
                code, source, self.redactor, document, line_offset, max_nodes=self.max_nodes
            )
        except (ValueError, RecursionError) as exc:
            self.diagnostic(source, str(exc) or "analysis recursion limit reached")
            return
        self.analyzed += 1
        collections = ("endpoints", "findings", "graphql_operations", "unresolved_requests")
        remaining = max(
            0,
            self.max_report_items
            + self.report_item_offset
            - sum(len(self.report[name]) for name in collections),
        )
        for name in collections:
            self.report[name].extend(result[name][:remaining])
            if len(result[name]) > remaining:
                self.diagnostic(source, "report item limit reached; extraction is partial")
            remaining = max(0, remaining - len(result[name]))
        if result["parse_errors"]:
            errors, size = len(result["parse_errors"]), sum(result["parse_errors"])
            # A grammar gap on one construct leaves a small ERROR region; everything around it
            # is still parsed and analyzed. Only larger damage makes the source incomplete.
            total = len(code) if isinstance(code, bytes) else len(code.encode("utf-8", "replace"))
            if errors <= 20 and size <= total // 100:
                self.diagnostic(
                    source,
                    f"{errors} small syntax region(s) ({size:,} bytes) could not be parsed; "
                    "the rest was analyzed",
                    "skipped",
                )
            else:
                self.diagnostic(
                    source, "syntax could not be fully parsed; extraction may be incomplete"
                )
        if not discover:
            return
        for dependency in result["dependencies"]:
            if dependency.startswith((".", "/", "http://", "https://")):
                self.enqueue(urljoin(source, dependency), "script", document)
        if self.source_maps:
            for reference in result["source_maps"]:
                if reference.startswith("data:"):
                    self.inline_map(reference, source, document)
                else:
                    self.enqueue(urljoin(source, reference), "map", document)

    def inline_map(self, data, source, document):
        try:
            header, payload = data.split(",", 1)
            if len(payload) > self.fetcher.max_bytes * 2:
                raise ValueError("inline source map byte limit reached")
            raw = (
                base64.b64decode(payload, validate=True)
                if header.endswith(";base64")
                else unquote_to_bytes(payload)
            )
            if len(raw) > self.fetcher.max_bytes:
                raise ValueError("inline source map byte limit reached")
            self.process_map(raw, source + "#inline-map", document)
        except (ValueError, UnicodeError) as exc:
            self.diagnostic(source, "invalid inline source map: " + str(exc))

    def process_map(self, raw, source, document, depth=0):
        try:
            value = json.loads(raw) if isinstance(raw, (bytes, str)) else raw
            if depth > 4 or not isinstance(value, dict) or value.get("version") != 3:
                raise ValueError("unsupported or deeply nested source map")
            if "sections" in value:
                for section in value["sections"][: self.max_files]:
                    if isinstance(section, dict) and "map" in section:
                        self.process_map(section["map"], source, document, depth + 1)
                    else:
                        self.diagnostic(
                            source, "external indexed-map sections are not fetched", "skipped"
                        )
                return
            names, contents = value.get("sources", []), value.get("sourcesContent", [])
            if not isinstance(names, list) or not isinstance(contents, list):
                raise ValueError("invalid source map sources")
            if not contents:
                self.diagnostic(source, "source map has no embedded sourcesContent", "skipped")
            for index, content in enumerate(contents[: self.max_files]):
                if not isinstance(content, str):
                    continue
                name = (
                    names[index]
                    if index < len(names) and isinstance(names[index], str)
                    else f"source-{index}.js"
                )
                # Map filenames are labels only: never local paths or network requests.
                label = source + "#source=" + name
                self.report["sources"].append(
                    {
                        "url": label,
                        "kind": "source_map_content",
                        "document_url": document,
                        "bytes": len(content.encode()),
                        "sha256": hashlib.sha256(content.encode()).hexdigest(),
                    }
                )
                if name.split("?", 1)[0].endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
                    self.process_code(content, label, document, discover=False)
            if len(contents) > self.max_files:
                self.diagnostic(source, "embedded source map file limit reached")
        except (ValueError, TypeError, AttributeError, RecursionError) as exc:
            self.diagnostic(source, "invalid source map: " + str(exc))

    async def run(self, targets):
        self.report["targets"] = targets
        # Process a bounded group of inputs at a time. A previous group's page,
        # file or byte budget must not prevent later supplied targets being fetched.
        max_files, max_pages = self.max_files, self.max_pages
        max_report_items = self.max_report_items
        max_total = getattr(self.fetcher, "max_total", None)
        try:
            for offset in range(0, len(targets), self.fetcher.concurrency):
                seeds = targets[offset : offset + self.fetcher.concurrency]
                self.max_files, self.max_pages = max_files * len(seeds), max_pages * len(seeds)
                self.max_report_items = max_report_items * len(seeds)
                self.report_item_offset = sum(
                    len(self.report[name])
                    for name in (
                        "endpoints",
                        "findings",
                        "graphql_operations",
                        "unresolved_requests",
                    )
                )
                if max_total is not None:
                    self.fetcher.max_total = max_total * len(seeds)
                    self.fetcher.total = 0
                self.pages = self.files = self.analysis_attempts = 0
                if self.links_not_crawled:
                    self.note_links()
                self.queue.clear()
                self.seen.clear()
                self.fetched.clear()
                self.cache.clear()
                await self.run_batch(seeds)
                if self.runtime:
                    await self.run_dynamic(seeds)
            self.note_links()
        finally:
            self.max_files, self.max_pages = max_files, max_pages
            self.max_report_items = max_report_items
            if max_total is not None:
                self.fetcher.max_total = max_total
            self.cache.clear()
        return self.finalize()

    @staticmethod
    def target_kind(url):
        path = urlsplit(url).path.lower()
        if path.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
            return "script"
        return "map" if path.endswith(".map") else "page"

    async def run_batch(self, targets):
        for url in targets:
            kind = self.target_kind(url)
            self.enqueue(url, kind, self.base_url if kind != "page" else None)
        while self.queue:
            batch = []
            while self.queue and len(batch) < self.fetcher.concurrency:
                item = self.queue.popleft()
                url, kind, document, depth = item
                if kind == "page":
                    if self.pages >= self.max_pages:
                        # Extra links are not part of the supplied input; count, don't fail.
                        self.links_not_crawled += 1
                        continue
                    self.pages += 1
                else:
                    if self.files >= self.max_files:
                        self.diagnostic(url, "script/source-map file limit reached")
                        continue
                    self.files += 1
                batch.append(item)
            responses = await asyncio.gather(
                *(self.cached_get(url, kind) for url, kind, _, _ in batch)
            )
            self.downloads += len(batch)
            for (url, kind, document, depth), response in zip(batch, responses, strict=True):
                self.report["sources"].append(
                    {**response.metadata(), "kind": kind, "document_url": document}
                )
                self.fetched.update({url, response.final_url})
                if response.error:
                    self.diagnostic(
                        url, response.error, code=response.error_code, hint=response.hint
                    )
                    continue
                final = response.final_url
                content_type = response.headers.get("content-type", "").lower()
                code = response.body.decode("utf-8-sig", "replace")
                is_html = "html" in content_type or code.lstrip().lower().startswith(
                    ("<!doctype html", "<html")
                )
                if kind == "map":
                    self.process_map(response.body, final, document)
                elif is_html and kind == "page":
                    page = Page(final, code)
                    for script in page.scripts:
                        self.enqueue(urljoin(page.base, script), "script", page.base)
                    for i, (inline, line) in enumerate(page.inline):
                        label = final + f"#inline-{i + 1}.js"
                        self.report["sources"].append(
                            {
                                "url": label,
                                "kind": "inline",
                                "document_url": page.base,
                                "bytes": len(inline.encode()),
                                "sha256": hashlib.sha256(inline.encode()).hexdigest(),
                            }
                        )
                        self.process_code(inline, label, page.base, line - 1)
                    if depth < self.depth:
                        for link in page.links:
                            linked = urljoin(page.base, link)
                            if urlsplit(linked).scheme in {"http", "https"}:
                                self.enqueue(linked, "page", None, depth + 1)
                elif is_html:
                    self.diagnostic(final, "expected JavaScript but received HTML")
                elif (
                    kind == "script" or "javascript" in content_type or "ecmascript" in content_type
                ):
                    self.process_code(code, final, document or self.base_url)
                else:
                    self.diagnostic(final, "unsupported document content type", "skipped")
                if kind != "map" and self.source_maps:
                    reference = response.headers.get("sourcemap") or response.headers.get(
                        "x-sourcemap"
                    )
                    if reference:
                        self.enqueue(urljoin(final, reference), "map", document)

    async def run_dynamic(self, targets):
        pages = [url for url in targets if self.target_kind(url) == "page"]
        results = await asyncio.gather(*(self.runtime.observe(url) for url in pages))
        for result in results:
            self.apply_runtime(result)

    def apply_runtime(self, result):
        from .dynamic import endpoint, sink_findings

        page = result.get("final_url") or result["page"]
        self.report["runtime"].append(
            {
                "page": page,
                "requests_seen": sum(not r["blocked"] for r in result["requests"]),
                "requests_blocked": sum(r["blocked"] for r in result["requests"]),
                "runtime_scripts": len(result["scripts"]),
                "marker_reached_sinks": len(result["sinks"]),
                "errors": result["errors"],
            }
        )
        for error in result["errors"]:
            self.diagnostic(page, "dynamic analysis: " + error)
        for url, body in result["scripts"]:
            # Scripts the static crawl already analyzed are not counted twice.
            if url in self.fetched:
                continue
            self.fetched.add(url)
            if self.files >= self.max_files:
                self.diagnostic(url, "script/source-map file limit reached")
                continue
            self.files += 1
            self.downloads += 1
            self.report["sources"].append(
                {
                    "url": url,
                    "kind": "runtime_script",
                    "document_url": page,
                    "bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
            )
            self.process_code(body.decode("utf-8-sig", "replace"), url, page, discover=False)
        self.report["endpoints"].extend(endpoint(r, page) for r in result["requests"])
        self.report["findings"].extend(sink_findings(result))

    def note_links(self):
        if self.links_not_crawled:
            self.diagnostic(
                "pages",
                f"{self.links_not_crawled} linked page(s) not crawled (page budget; "
                "raise --max-pages to include them)",
                "skipped",
            )
            self.links_not_crawled = 0

    async def cached_get(self, url, kind):
        # Cache by kind as page and asset scopes differ. Tasks also coalesce in-flight requests.
        key = (url, kind)
        if key not in self.cache:
            self.cache[key] = asyncio.create_task(self.fetcher.get(url, kind))
        result = await self.cache[key]
        # Keep cached source bodies bounded even when the input list is very large.
        completed = [(k, t) for k, t in self.cache.items() if t.done() and not t.cancelled()]
        size = sum(len(t.result().body) for _, t in completed if t.exception() is None)
        for cached_key, task in completed:
            if size <= 64_000_000 and len(self.cache) <= 128:
                break
            if task.exception() is None:
                size -= len(task.result().body)
            self.cache.pop(cached_key, None)
        return result

    def merge_runtime(self):
        """A request seen at runtime that static analysis also found marks that endpoint as
        observed instead of appearing twice."""
        static = {}
        for item in self.report["endpoints"]:
            if (
                item["library"] != "browser"
                and item["url"]
                and "{{" not in item["url"].split("?")[0]
            ):
                static.setdefault((item["method"], item["url"].split("?")[0]), []).append(item)
        kept = []
        for item in self.report["endpoints"]:
            matches = item["library"] == "browser" and static.get(
                (item["method"], item["url"].split("?")[0])
            )
            if not matches:
                kept.append(item)
                continue
            # Every static copy (the same script can be analyzed for several pages) gets the
            # same mark, so identical records still merge below.
            for match in matches:
                match["observed_at_runtime"] = True
                if item.get("execution") == "blocked":
                    match["blocked_at_runtime"] = True
                match["evidence"].extend(e for e in item["evidence"] if e not in match["evidence"])
        self.report["endpoints"] = kept
        # A static review clue on the same line as a runtime observation is replaced by it.
        observed = {
            (f["evidence"]["source"], f["evidence"]["line"])
            for f in self.report["findings"]
            if f.get("observed") == "runtime"
        }
        for finding in self.report["findings"]:
            location = (finding["evidence"]["source"], finding["evidence"]["line"])
            if finding.get("observed") != "runtime" and location in observed:
                finding["superseded_by_runtime"] = True

    def finalize(self):
        self.merge_runtime()
        unique = {}
        for item in self.report["endpoints"]:
            key = json.dumps({k: v for k, v in item.items() if k != "evidence"}, sort_keys=True)
            if key in unique:
                for evidence in item["evidence"]:
                    if evidence not in unique[key]["evidence"]:
                        unique[key]["evidence"].append(evidence)
            else:
                unique[key] = item
        self.report["endpoints"] = sorted(
            unique.values(), key=lambda e: (e["url"] or e["url_template"], e["method"] or "")
        )
        for collection in ("findings", "graphql_operations", "diagnostics"):
            seen = set()
            values = []
            for item in self.report[collection]:
                key = json.dumps(item, sort_keys=True)
                if key not in seen:
                    seen.add(key)
                    values.append(item)
            self.report[collection] = values
        self.report["summary"] = {
            "targets": len(self.report["targets"]),
            "downloads": self.downloads,
            "analyzed_sources": self.analyzed,
            "endpoints": len(unique),
            "review_items": sum(
                f["priority"] != "low" and not f.get("superseded_by_runtime")
                for f in self.report["findings"]
            ),
            "confirmed": sum(f.get("status") == "confirmed" for f in self.report["findings"]),
            "seen_at_runtime": sum(bool(e.get("observed_at_runtime")) for e in unique.values()),
            "unresolved_requests": len(self.report["unresolved_requests"]),
            "incomplete": sum(d["category"] == "incomplete" for d in self.report["diagnostics"]),
        }
        self.report["finished_at"] = datetime.now(UTC).isoformat()
        self.report["complete"] = self.report["summary"]["incomplete"] == 0
        report = self.redactor.clean(self.report)
        for request in report["endpoints"]:
            if request["curl"] is not None:
                request["curl"] = curl_example(request)
            request["template_only"] = True
        return report
