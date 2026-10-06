import hashlib
import json
import math
import re
from collections import Counter

from .syntax import args, field, member, text

SENSITIVE = re.compile(
    r"(?:password|passwd|client[_-]?secret|secret[_-]?access[_-]?key|private[_-]?key|signing[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie)",
    re.I,
)
TOKEN_PATTERNS = (
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"),
    ),
    ("stripe_secret_key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,200}\b")),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
            r"[\s\S]{32,16000}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
    ),
)


def entropy(value):
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values())


class Redactor:
    def __init__(self):
        self.values = set()

    def add(self, value):
        if isinstance(value, str) and len(value) >= 4 and "{{" not in value:
            self.values.add(value)
            self.values.add(json.dumps(value, ensure_ascii=True)[1:-1])

    def clean(self, value):
        if isinstance(value, dict):
            if (
                {"name", "value"} <= value.keys()
                and re.fullmatch(
                    r"token|access_token|refresh_token|password|client_secret|api_key|apikey",
                    str(value["name"]),
                    re.I,
                )
                and isinstance(value["value"], str)
                and "{{" not in value["value"]
            ):
                value = {**value, "value": "{{REDACTED}}"}
            return {
                self.clean(k): "{{REDACTED}}"
                if SENSITIVE.search(str(k)) and isinstance(v, str) and "{{" not in v
                else self.clean(v)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.clean(v) for v in value]
        if isinstance(value, str):
            for secret in sorted(self.values, key=len, reverse=True):
                value = value.replace(secret, "{{REDACTED}}")
            value = re.sub(
                r"([?&](?:access_token|refresh_token|token|password|client_secret|api_key)=)[^&#\s'\"]+",
                r"\1{{REDACTED}}",
                value,
                flags=re.I,
            )
        return value


def evidence(node, source, line_offset=0):
    return {
        "source": source,
        "line": node.start_point.row + 1 + line_offset,
        "column": node.start_point.column + 1,
        "snippet": text(node)[:500],
    }


def scan_security(syntax, source, redactor, line_offset=0):
    findings, seen = [], set()

    def add(rule, node, title, check, priority="medium", **extra):
        key = (rule, node.start_byte)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            {
                "rule": rule,
                "title": title,
                "priority": priority,
                "status": "needs_review",
                "check": check,
                "evidence": evidence(node, source, line_offset),
                **extra,
            }
        )

    for node in syntax.nodes:
        if node.type not in {"string", "template_string", "comment"}:
            continue
        value = text(node) if node.type == "comment" else syntax.eval(node)
        if not isinstance(value, str):
            continue
        parent = node.parent
        keynode = field(parent, "key") or field(parent, "name")
        key = text(keynode).strip("'\"")
        # Mask sensitive property values even when they are too weak to be a finding.
        if key and SENSITIVE.search(key):
            redactor.add(value)
            redactor.values.add(text(node))
            if (
                len(value) >= 20
                and "{{" not in value
                and entropy(value) >= 3.5
                and not re.search(r"example|placeholder|your[_ -]|changeme|dummy|test", value, re.I)
                and not any(pattern.search(value) for _, pattern in TOKEN_PATTERNS)
            ):
                add(
                    "hardcoded_credential",
                    node,
                    "Credential-like value embedded in JavaScript",
                    "Check whether this is a real credential and what access it grants; "
                    "it was not tested.",
                    "high",
                    field=key,
                    fingerprint=hashlib.sha256(value.encode()).hexdigest(),
                )
        for rule, pattern in TOKEN_PATTERNS:
            for match in pattern.finditer(value):
                secret = match.group()
                redactor.add(secret)
                redactor.add(text(node)[1:-1])
                add(
                    rule,
                    node,
                    "Credential-format value embedded in JavaScript",
                    "Confirm ownership, validity and permissions before reporting. "
                    "No credential was used.",
                    "high",
                    fingerprint=hashlib.sha256(secret.encode()).hexdigest(),
                )

    def source_of(node, depth=0):
        if node is None or depth > 10:
            return None
        name = member(node)
        if (
            name
            in {
                "location.search",
                "location.hash",
                "location.href",
                "document.URL",
                "document.referrer",
                "window.name",
                "window.location.search",
                "window.location.hash",
                "window.location.href",
            }
            and syntax.binding_key(name.split(".")[0], node) is None
        ):
            return name
        if node.type == "identifier":
            return source_of(syntax.initializer(node), depth + 1)
        if name.endswith(".data"):
            receiver = name.rsplit(".", 1)[0]
            for scope in syntax.scopes(node):
                parent = scope.parent
                if (
                    scope.type in {"arrow_function", "function_expression"}
                    and parent
                    and parent.type == "arguments"
                ):
                    call = parent.parent
                    callargs = args(call)
                    params = field(scope, "parameters") or field(scope, "parameter")
                    identifiers = [
                        text(n)
                        for n in (
                            params.named_children
                            if params and params.type == "formal_parameters"
                            else [params]
                        )
                        if n
                    ]
                    if (
                        member(field(call, "function"))
                        in {"addEventListener", "window.addEventListener"}
                        and callargs
                        and syntax.eval(callargs[0]) == "message"
                        and receiver in identifiers
                    ):
                        return "message event data"
        if node.type in {
            "binary_expression",
            "template_string",
            "template_substitution",
            "parenthesized_expression",
        }:
            return next(
                (found for child in node.named_children if (found := source_of(child, depth + 1))),
                None,
            )
        if node.type == "call_expression":
            function = member(field(node, "function"))
            if function in {
                "decodeURI",
                "decodeURIComponent",
                "String",
                "JSON.parse",
            } or function.endswith((".slice", ".substring", ".substr", ".trim", ".get")):
                candidates = args(node) + (
                    [field(field(node, "function"), "object")] if "." in function else []
                )
                return next(
                    (found for child in candidates if (found := source_of(child, depth + 1))), None
                )
        if (
            node.type == "new_expression"
            and member(field(node, "constructor")) == "URLSearchParams"
        ):
            return next(
                (found for child in args(node) if (found := source_of(child, depth + 1))), None
            )
        return None

    for node in syntax.nodes:
        value, sink, rule = None, "", ""
        if node.type == "assignment_expression":
            sink = member(field(node, "left"))
            if sink.endswith((".innerHTML", ".outerHTML", ".srcdoc")):
                value, rule = field(node, "right"), "dom_html_flow"
                if sink.startswith("."):
                    sink = text(field(node, "left"))[:150]
            elif sink in {"location", "window.location", "location.href", "window.location.href"}:
                value, rule = field(node, "right"), "redirect_flow"
        if node.type == "call_expression":
            function, callargs = member(field(node, "function")), args(node)
            if (
                function
                in {
                    "eval",
                    "window.eval",
                    "document.write",
                    "document.writeln",
                    "location.assign",
                    "location.replace",
                    "window.location.assign",
                    "window.location.replace",
                }
                and callargs
                and syntax.global_name(field(node, "function"), function)
            ):
                value, sink = callargs[0], function
                rule = (
                    "dynamic_code_flow"
                    if "eval" in function
                    else "redirect_flow"
                    if "location" in function
                    else "dom_html_flow"
                )
            elif function.endswith(".insertAdjacentHTML") and len(callargs) > 1:
                value, sink, rule = callargs[1], function, "dom_html_flow"
            elif (
                function in {"fetch", "window.fetch"}
                and callargs
                and syntax.global_name(field(node, "function"), function)
            ):
                value, sink, rule = callargs[0], function, "request_url_flow"
            if (
                function
                in {
                    "localStorage.setItem",
                    "sessionStorage.setItem",
                    "window.localStorage.setItem",
                    "window.sessionStorage.setItem",
                }
                and len(callargs) > 1
            ):
                key = syntax.eval(callargs[0])
                if isinstance(key, str) and re.search(
                    r"token|password|secret|session|jwt", key, re.I
                ):
                    add(
                        "sensitive_browser_storage",
                        node,
                        "Sensitive-looking data written to browser storage",
                        "Check what is stored and which scripts can read it. "
                        "Storage use alone is not a vulnerability.",
                    )
            if (
                function.endswith(".postMessage")
                and len(callargs) > 1
                and syntax.eval(callargs[1]) == "*"
            ):
                payload = syntax.eval(callargs[0])
                if isinstance(payload, dict) and any(SENSITIVE.search(k) for k in payload):
                    add(
                        "sensitive_wildcard_message",
                        node,
                        "Sensitive-looking fields sent with wildcard target origin",
                        "Check the destination window, navigation risk "
                        "and actual data sensitivity.",
                    )
        if rule and (origin := source_of(value)):
            add(
                rule,
                node,
                f"{origin} reaches {sink}",
                "Trace guards, sanitizers and runtime reachability; "
                "this local static flow is not an exploit proof.",
                source_expression=origin,
                sink=sink,
            )
    return findings
