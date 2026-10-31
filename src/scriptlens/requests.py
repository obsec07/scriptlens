import json
import re
import shlex
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

from .security import evidence
from .syntax import Object, Unknown, args, complete, display, field, member, text

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def as_object(value):
    return value if isinstance(value, dict) else Object(complete=False)


def body_info(syntax, node, family):
    if node is None:
        return {"kind": "none", "value": None, "complete": True}
    use = node
    resolved = syntax.initializer(node) if node.type == "identifier" else None
    if resolved is not None:
        node = resolved
    name = member(field(node, "function") or field(node, "constructor"))
    arguments = args(node)
    if node.type == "call_expression" and name == "JSON.stringify" and arguments:
        value = syntax.eval(arguments[0])
        return {"kind": "json", "value": display(value), "complete": complete(value)}
    if node.type == "new_expression" and name in {"URLSearchParams", "FormData"}:
        value = syntax.eval(arguments[0]) if arguments else Object()
        if isinstance(value, str) and name == "URLSearchParams":
            value = Object(parse_qsl(value, keep_blank_values=True))
        value = as_object(value)
        if use.type == "identifier":
            key = syntax.binding_key(text(use), use)
            calls = syntax.calls_by_binding.get(key, [])
            for call in calls[:256]:
                if not node.end_byte < call.start_byte < use.start_byte:
                    continue
                operation = text(field(field(call, "function"), "property"))
                callargs = args(call)
                if operation not in {"append", "set"} or len(callargs) < 2:
                    value.complete = False
                    continue
                key_value = syntax.eval(callargs[0])
                if not isinstance(key_value, str) or syntax.scope(call) != syntax.scope(use):
                    value.complete = False
                    continue
                item = syntax.eval(callargs[1])
                if operation == "append" and key_value in value:
                    old = value[key_value]
                    value[key_value] = (old if isinstance(old, list) else [old]) + [item]
                else:
                    value[key_value] = item
            if len(calls) > 256:
                value.complete = False
        return {
            "kind": "multipart" if name == "FormData" else "urlencoded",
            "value": display(value),
            "complete": complete(value),
        }
    value = syntax.eval(node)
    kind = (
        "json"
        if family == "axios" and isinstance(value, (dict, list))
        else "urlencoded"
        if family == "jquery" and isinstance(value, dict)
        else "raw"
    )
    return {"kind": kind, "value": display(value), "complete": complete(value)}


def property_node(syntax, node, key, depth=0):
    if node is None or depth > 10:
        return None
    if node.type == "identifier":
        return property_node(syntax, syntax.initializer(node), key, depth + 1)
    if node.type != "object":
        return None
    found = None
    for child in node.named_children:
        if child.type == "pair":
            name = field(child, "key")
            literal = syntax.eval(name) if name.type == "string" else text(name)
            if literal == key:
                found = field(child, "value")
        elif child.type == "spread_element":
            spread = property_node(syntax, child.named_children[0], key, depth + 1)
            # A spread can replace or introduce any field, so retain uncertainty.
            found = spread
    return found


def curl_example(request):
    method, url = request["method"], request["url"] or request["url_template"]
    if method not in METHODS or not isinstance(url, str):
        return None
    if url.startswith("/") or not re.match(r"^(?:https?://|\{\{BASE_URL\}\})", url):
        return None
    if re.search(r"[\x00-\x1f\x7f]", url):
        return None
    command = ["curl", "--globoff", "--request", method, "--url", url]
    for name, value in request["headers"].items():
        if not isinstance(value, str):
            value = str(value)
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or re.search(
            r"[\r\n\x00]", value
        ):
            continue
        command += ["--header", f"{name}: {value}"]
    body = request["body"]
    if body["kind"] == "json":
        command += [
            "--data-raw",
            body["value"]
            if isinstance(body["value"], str) and body["value"].startswith("{{")
            else json.dumps(body["value"], ensure_ascii=True, separators=(",", ":")),
        ]
    elif body["kind"] == "urlencoded":
        value = body["value"]
        command += [
            "--data-raw",
            urlencode(value, doseq=True) if isinstance(value, dict) else str(value),
        ]
    elif body["kind"] == "multipart":
        if isinstance(body["value"], dict) and body["value"]:
            for name, value in body["value"].items():
                for item in value if isinstance(value, list) else [value]:
                    command += ["--form-string", f"{name}={item}"]
        else:
            command += ["--form-string", "{{FIELD_NAME}}={{FIELD_VALUE}}"]
    elif body["kind"] == "raw":
        command += ["--data-raw", body["value"] if isinstance(body["value"], str) else "{{BODY}}"]
    return shlex.join(command)


def review_checks(path, method):
    checks = []
    if re.search(r"/(?:admin|internal|manage)(?:/|$)", path, re.I):
        checks.append("Check server-side role enforcement using authorized accounts")
    if re.search(r"/(?:users?|accounts?|tenants?|orders?|files?)(?:/|$)|\{\{", path, re.I):
        checks.append("Check object and tenant access with two authorized accounts")
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        checks.append("Review authentication, CSRF protection and accepted body fields")
    return checks


def request_record(
    syntax,
    node,
    family,
    url_value,
    method,
    options,
    body,
    source,
    document_url,
    line_offset,
    base_url=None,
    notes=(),
):
    raw = display(url_value)
    has_url = isinstance(raw, str) and (
        raw.startswith(("/", "http://", "https://", "ws://", "wss://"))
        or re.match(r"^\{\{[^{}]+\}\}/[^{}]", raw)
        or (raw and not raw.startswith("{{") and not re.search(r"\s", raw))
    )
    if not has_url:
        return None
    if urlsplit(raw).scheme not in {"", "http", "https", "ws", "wss"}:
        return None
    notes = list(notes)
    method = method.upper() if isinstance(method, str) else None
    if method not in METHODS and method not in {"WEBSOCKET", "SSE"}:
        method = None
        notes.append("HTTP method depends on runtime code")
    template = raw
    if isinstance(base_url, str) and base_url:
        if not raw.startswith(("http://", "https://", "//", "ws://", "wss://")):
            template = base_url.rstrip("/") + "/" + raw.lstrip("/")
    elif isinstance(base_url, Unknown):
        template = display(base_url).rstrip("/") + "/" + raw.lstrip("/")
        notes.append("Axios baseURL is unresolved")
    absolute = None
    if template.startswith(("http://", "https://", "ws://", "wss://")):
        absolute = template
    elif not template.startswith("{{") and document_url:
        absolute = urljoin(document_url, template)
    elif not template.startswith("{{"):
        template = "{{BASE_URL}}/" + template.lstrip("/")
        notes.append("Document URL is unknown; set --base-url for direct JS files")
    if method == "WEBSOCKET" and absolute:
        if absolute.startswith("https://"):
            absolute = "wss://" + absolute[8:]
        elif absolute.startswith("http://"):
            absolute = "ws://" + absolute[7:]
    url = absolute or template
    params = options.get("params", {})
    if isinstance(params, dict) and params:
        encoded = urlencode(display(params), doseq=True)
        url += ("&" if "?" in url else "?") + encoded
        if absolute:
            absolute = url
        else:
            template = url
    elif not complete(params):
        notes.append("Query parameters depend on runtime code")
    headers = options.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}
        notes.append("Headers depend on runtime code")
    headers = display(headers)
    if not complete(options):
        notes.append("Some request configuration is dynamic")
    if (
        body["kind"] in {"json", "urlencoded"}
        and family in {"axios", "jquery"}
        and not any(k.lower() == "content-type" for k in headers)
    ):
        headers["Content-Type"] = (
            "application/json" if body["kind"] == "json" else "application/x-www-form-urlencoded"
        )
    if body["kind"] != "none" and not body["complete"]:
        notes.append("Request body contains runtime values or unrecovered fields")
    if body["kind"] == "multipart":
        notes.append("Multipart curl uses text placeholders; choose file upload fields manually")
    if method in {"GET", "HEAD"} and body["kind"] != "none":
        notes.append("Body on GET/HEAD needs manual review; no curl generated")
    path = urlsplit(absolute).path if absolute else template
    checks = review_checks(path, method)
    record = {
        "method": method,
        "url": absolute,
        "url_template": template,
        "library": family,
        "headers": headers,
        "body": body,
        "query_parameters": [
            {"name": k, "value": v}
            for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        ],
        "credentials_mode": display(
            options.get("credentials", options.get("withCredentials", "not specified"))
        ),
        "evidence": [evidence(node, source, line_offset)],
        "notes": list(dict.fromkeys(notes)),
        "suggested_checks": checks,
        "execution": "not_sent",
    }
    record["curl"] = (
        None
        if method in {"WEBSOCKET", "SSE"} or (method in {"GET", "HEAD"} and body["kind"] != "none")
        else curl_example(record)
    )
    return record


def extract_requests(syntax, source, document_url=None, line_offset=0):
    requests, unresolved = [], []

    def url_expression(node):
        if node.type == "new_expression" and syntax.global_name(field(node, "constructor"), "URL"):
            values = args(node)
            if len(values) == 2:
                path, base = syntax.eval(values[0]), syntax.eval(values[1])
                if not isinstance(base, str) and document_url:
                    expression = member(values[1])
                    if expression in {"location.origin", "window.location.origin"}:
                        parts = urlsplit(document_url)
                        base = parts.scheme + "://" + parts.netloc + "/"
                    elif expression == "document.baseURI":
                        base = document_url
                if isinstance(path, str) and isinstance(base, str):
                    return urljoin(base, path)
        return syntax.eval(node)

    def merge_options(options, extra):
        old_headers = options.get("headers", {})
        options.update(extra)
        if isinstance(old_headers, dict) and isinstance(extra.get("headers"), dict):
            options["headers"] = {**old_headers, **extra["headers"]}
        options.complete &= getattr(extra, "complete", True)

    def axios_config(receiver):
        if syntax.library(receiver, "axios"):
            return Object()
        initial = syntax.initializer(receiver)
        if initial and initial.type == "call_expression":
            function = field(initial, "function")
            if text(field(function, "property")) == "create" and syntax.library(
                field(function, "object"), "axios"
            ):
                return as_object(syntax.eval(args(initial)[0])) if args(initial) else Object()
        return None

    for node in syntax.nodes:
        if node.type not in {"call_expression", "new_expression"} or node.has_error:
            continue
        function = field(node, "function") or field(node, "constructor")
        name, callargs = member(function), args(node)
        family, url_value, method, body, options = None, None, None, None, Object()
        notes, base = [], None
        if (
            name in {"fetch", "window.fetch", "globalThis.fetch"}
            and syntax.global_name(function, name)
            and callargs
        ):
            family = "fetch"
            urlnode = callargs[0]
            options_node = callargs[1] if len(callargs) > 1 else None
            if (
                urlnode.type == "new_expression"
                and member(field(urlnode, "constructor")) == "Request"
            ):
                inner = args(urlnode)
                if inner:
                    urlnode = inner[0]
                if len(inner) > 1 and options_node is None:
                    options_node = inner[1]
            options = as_object(syntax.eval(options_node)) if options_node else Object()
            method = options.get("method", "GET" if getattr(options, "complete", True) else None)
            url_value = url_expression(urlnode)
            body = body_info(syntax, property_node(syntax, options_node, "body"), family)
        elif (
            node.type == "new_expression"
            and name in {"WebSocket", "EventSource"}
            and callargs
            and syntax.global_name(function, name)
        ):
            family, method, url_value = (
                name.lower(),
                "WEBSOCKET" if name == "WebSocket" else "SSE",
                syntax.eval(callargs[0]),
            )
        else:
            receiver, operation = field(function, "object"), text(field(function, "property"))
            config = axios_config(receiver) if receiver else axios_config(function)
            if config is not None:
                family = "axios"
                options = Object(config, complete=getattr(config, "complete", True))
                if (
                    operation in {"get", "delete", "head", "options", "post", "put", "patch"}
                    and callargs
                ):
                    url_value, method = syntax.eval(callargs[0]), operation.upper()
                    index = 2 if operation in {"post", "put", "patch"} else 1
                    optnode = callargs[index] if len(callargs) > index else None
                    extra = as_object(syntax.eval(optnode)) if optnode else Object()
                    merge_options(options, extra)
                    bodynode = (
                        callargs[1]
                        if index == 2 and len(callargs) > 1
                        else property_node(syntax, optnode, "data")
                    )
                    body = body_info(syntax, bodynode, family)
                elif operation in {"", "request"} and callargs:
                    if isinstance(syntax.eval(callargs[0]), str):
                        url_value = syntax.eval(callargs[0])
                        optnode = callargs[1] if len(callargs) > 1 else None
                    else:
                        optnode = callargs[0]
                    extra = as_object(syntax.eval(optnode)) if optnode else Object()
                    merge_options(options, extra)
                    url_value = options.get("url", url_value)
                    method = options.get(
                        "method", "GET" if getattr(options, "complete", True) else None
                    )
                    body = body_info(syntax, property_node(syntax, optnode, "data"), family)
                else:
                    continue
                base = options.get("baseURL")
                notes.append("Axios defaults, interceptors and runtime transforms are not executed")
            elif (
                receiver
                and syntax.library(receiver, "jquery")
                and operation in {"ajax", "get", "post", "getJSON"}
                and callargs
            ):
                family = "jquery"
                if operation == "ajax":
                    optnode = (
                        callargs[0]
                        if isinstance(syntax.eval(callargs[0]), dict)
                        else callargs[1]
                        if len(callargs) > 1
                        else None
                    )
                    options = as_object(syntax.eval(optnode)) if optnode else Object()
                    url_value = options.get("url", syntax.eval(callargs[0]))
                    method = options.get(
                        "method",
                        options.get("type", "GET" if getattr(options, "complete", True) else None),
                    )
                    bodynode = property_node(syntax, optnode, "data")
                else:
                    url_value, method = (
                        syntax.eval(callargs[0]),
                        "POST" if operation == "post" else "GET",
                    )
                    bodynode = (
                        callargs[1]
                        if len(callargs) > 1
                        and callargs[1].type not in {"function_expression", "arrow_function"}
                        else None
                    )
                body = body_info(syntax, bodynode, family)
                if method == "GET" and isinstance(body["value"], dict):
                    options["params"] = body["value"]
                    body = None
                if options.get("contentType"):
                    options["headers"] = {
                        **as_object(options.get("headers")),
                        "Content-Type": options["contentType"],
                    }
            elif name == "navigator.sendBeacon" and callargs and syntax.global_name(function, name):
                family, method, url_value = "beacon", "POST", syntax.eval(callargs[0])
                body = body_info(syntax, callargs[1] if len(callargs) > 1 else None, family)
            elif receiver and operation == "open" and len(callargs) >= 2:
                initial = syntax.initializer(receiver)
                if (
                    not initial
                    or initial.type != "new_expression"
                    or member(field(initial, "constructor")) != "XMLHttpRequest"
                ):
                    continue
                family, method, url_value = (
                    "xhr",
                    syntax.eval(callargs[0]),
                    syntax.eval(callargs[1]),
                )
                # Pair only a linear open/header/send sequence in the same statement block.
                block = node.parent.parent
                options = Object(headers={})
                body = {"kind": "raw", "value": "{{BODY}}", "complete": False}
                receiver_key = syntax.binding_key(member(receiver), node)
                calls = syntax.calls_by_binding.get(receiver_key, [])
                position = next((i for i, call in enumerate(calls) if call == node), len(calls))
                for other in calls[position + 1 : position + 129]:
                    if (
                        other.start_byte <= node.end_byte
                        or other.type != "call_expression"
                        or other.parent.parent != block
                    ):
                        continue
                    otherfn, otherargs = field(other, "function"), args(other)
                    if member(field(otherfn, "object")) != member(receiver):
                        continue
                    action = text(field(otherfn, "property"))
                    if action == "open":
                        break
                    if action == "setRequestHeader" and len(otherargs) == 2:
                        key = syntax.eval(otherargs[0])
                        if isinstance(key, str):
                            options["headers"][key] = syntax.eval(otherargs[1])
                    if action == "send":
                        body = body_info(syntax, otherargs[0] if otherargs else None, family)
                        break
                notes.append(
                    "XHR body/header pairing covers only a linear sequence in the same block"
                )
        if family is None:
            continue
        record = request_record(
            syntax,
            node,
            family,
            url_value,
            method,
            options,
            body or {"kind": "none", "value": None, "complete": True},
            source,
            document_url,
            line_offset,
            base,
            notes,
        )
        if record:
            requests.append(record)
        else:
            unresolved.append(
                {
                    "reason": "request URL has no recoverable static prefix",
                    "library": family,
                    "evidence": evidence(node, source, line_offset),
                }
            )
    return requests, unresolved
