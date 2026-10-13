import re

from .requests import extract_requests
from .security import SENSITIVE, evidence, scan_security
from .syntax import Syntax, args, field, member, text


def analyze(code, source, redactor, document_url=None, line_offset=0, *, max_nodes=250_000):
    syntax = Syntax(code, source, max_nodes=max_nodes)
    requests, unresolved = extract_requests(syntax, source, document_url, line_offset)
    findings = scan_security(syntax, source, redactor, line_offset)
    for request in requests:
        for key, value in request["headers"].items():
            if SENSITIVE.search(key) or "api-key" in key.lower():
                redactor.add(value)
                request["headers"][key] = (
                    "{{REDACTED}}" if isinstance(value, str) and "{{" not in value else value
                )
    dependencies, maps, graphql = [], [], []
    for node in syntax.nodes:
        if node.type in {"import_statement", "export_statement"}:
            child = field(node, "source")
            value = syntax.eval(child)
            if isinstance(value, str) and value.startswith((".", "/", "http://", "https://")):
                dependencies.append(value)
        if node.type in {"call_expression", "new_expression"}:
            function = field(node, "function") or field(node, "constructor")
            name, callargs = member(function) or text(function), args(node)
            if name in {"import", "importScripts", "Worker", "SharedWorker"}:
                for child in callargs[:1] if name != "importScripts" else callargs:
                    value = syntax.eval(child)
                    if isinstance(value, str) and "{{" not in value:
                        dependencies.append(value)
            arguments = field(node, "arguments")
            if name in {"gql", "graphql"} and arguments and arguments.type == "template_string":
                query = syntax.eval(arguments)
                if isinstance(query, str):
                    graphql.append(graphql_record(query, evidence(node, source, line_offset)))
        if node.type == "comment":
            match = re.search(r"[#@]\s*sourceMappingURL\s*=\s*(\S+)", text(node))
            if match:
                maps.append(match.group(1).removesuffix("*/"))
    for request in requests:
        body = request["body"]["value"]
        if isinstance(body, dict) and isinstance(body.get("query"), str):
            graphql.append(
                graphql_record(
                    body["query"], request["evidence"][0], request["url"] or request["url_template"]
                )
            )
    return {
        "endpoints": requests,
        "findings": findings,
        "unresolved_requests": unresolved,
        "dependencies": list(dict.fromkeys(dependencies)),
        "source_maps": list(dict.fromkeys(maps)),
        "graphql_operations": graphql,
        "parse_errors": syntax.tree.root_node.has_error,
    }


def graphql_record(query, location, endpoint=None):
    return {
        "query": query,
        "endpoint": endpoint,
        "operations": [
            {"type": m[0], "name": m[1]}
            for m in re.findall(
                r"\b(query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]*)", query
            )
        ],
        "variables": sorted(set(re.findall(r"\$([_A-Za-z][_0-9A-Za-z]*)\s*:", query))),
        "evidence": location,
        "status": "source_observation",
        "execution": "not_sent",
    }
