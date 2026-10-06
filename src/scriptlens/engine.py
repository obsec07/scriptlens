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
from .inputs import normalize_url
from .requests import curl_example
from .security import Redactor


class Engine:
    def __init__(
        self, fetcher, *, max_files=100, max_pages=10, depth=1, source_maps=True, base_url=None
    ):
        self.fetcher, self.scope = fetcher, fetcher.scope
        self.max_files, self.max_pages, self.depth = max_files, max_pages, depth
        self.source_maps, self.base_url = source_maps, base_url
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
        self.pages = self.files = self.analyzed = 0

    def diagnostic(self, url, reason, category="incomplete"):
        self.report["diagnostics"].append({"source": url, "category": category, "reason": reason})

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
            self.diagnostic(
                url, "outside scope; add an authorized --asset-host or --scope", "skipped"
            )
            return
        if len(self.queue) >= (self.max_files + self.max_pages) * 4:
            if not any(
                d["reason"] == "discovery queue limit reached" for d in self.report["diagnostics"]
            ):
                self.diagnostic(url, "discovery queue limit reached")
            return
        self.queue.append((url, kind, document, depth))

    def process_code(self, code, source, document=None, line_offset=0, discover=True):
        if self.analyzed >= self.max_files * 4:
            self.diagnostic(source, "analysis unit limit reached")
            return
        self.analyzed += 1
        try:
            result = analyze(code, source, self.redactor, document, line_offset)
        except (ValueError, RecursionError) as exc:
            self.diagnostic(source, str(exc) or "analysis recursion limit reached")
            return
        collections = ("endpoints", "findings", "graphql_operations", "unresolved_requests")
        remaining = max(0, 25_000 - sum(len(self.report[name]) for name in collections))
        for name in collections:
            self.report[name].extend(result[name][:remaining])
            if len(result[name]) > remaining:
                self.diagnostic(source, "report item limit reached; extraction is partial")
            remaining = max(0, remaining - len(result[name]))
        if result["parse_errors"]:
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
        for url in targets:
            path = urlsplit(url).path.lower()
            kind = (
                "script"
                if path.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"))
                else "map"
                if path.endswith(".map")
                else "page"
            )
            self.enqueue(url, kind, self.base_url if kind != "page" else None)
        while self.queue:
            batch = []
            while self.queue and len(batch) < self.fetcher.concurrency:
                item = self.queue.popleft()
                url, kind, document, depth = item
                if kind == "page":
                    if self.pages >= self.max_pages:
                        self.diagnostic(url, "page limit reached")
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
            for (url, kind, document, depth), response in zip(batch, responses, strict=True):
                self.report["sources"].append(
                    {**response.metadata(), "kind": kind, "document_url": document}
                )
                if response.error:
                    self.diagnostic(url, response.error)
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
        return self.finalize()

    async def cached_get(self, url, kind):
        # Cache by kind as page and asset scopes differ. Tasks also coalesce in-flight requests.
        key = (url, kind)
        if key not in self.cache:
            self.cache[key] = asyncio.create_task(self.fetcher.get(url, kind))
        return await self.cache[key]

    def finalize(self):
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
            "downloads": len(self.cache),
            "analyzed_sources": self.analyzed,
            "endpoints": len(unique),
            "review_items": len(self.report["findings"]),
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
