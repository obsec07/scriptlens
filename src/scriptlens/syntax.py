"""Bounded literal/constant evaluation. Never execute downloaded JavaScript."""

import json
import re
from dataclasses import dataclass

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Parser

FUNCTIONS = {
    "arrow_function",
    "function_expression",
    "function_declaration",
    "generator_function",
    "method_definition",
}
SCOPES = FUNCTIONS | {
    "program",
    "statement_block",
    "catch_clause",
    "for_statement",
    "for_in_statement",
}
LANGUAGES = {
    "js": Language(tree_sitter_javascript.language()),
    "ts": Language(tree_sitter_typescript.language_typescript()),
    "tsx": Language(tree_sitter_typescript.language_tsx()),
}


@dataclass(frozen=True)
class Unknown:
    expression: str


class Object(dict):
    def __init__(self, *args, complete=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.complete = complete


def text(node):
    return node.text.decode("utf-8", "replace") if node else ""


def walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def field(node, name):
    return node.child_by_field_name(name) if node else None


def args(node):
    arguments = field(node, "arguments")
    return arguments.named_children if arguments and arguments.type == "arguments" else []


def member(node):
    if not node:
        return ""
    if node.type in {"identifier", "property_identifier"}:
        return text(node)
    if node.type == "member_expression":
        return member(field(node, "object")) + "." + text(field(node, "property"))
    if node.type == "subscript_expression":
        index = field(node, "index")
        if index and index.type == "string":
            return member(field(node, "object")) + "." + literal_string(text(index))
    return ""


def literal_string(raw):
    body = raw[1:-1]
    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}

    def decode(match):
        code = match.group(1)
        if code.startswith("u{"):
            try:
                return chr(int(code[2:-1], 16))
            except ValueError:
                return "\ufffd"
        if code.startswith(("u", "x")) and len(code) > 1:
            return chr(int(code[1:], 16))
        if code in {"\n", "\r\n", "\r"}:
            return ""
        return escapes.get(code, code)

    return re.sub(
        r"\\(u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|\r\n|[\s\S])", decode, body
    )


def complete(value):
    if isinstance(value, Unknown):
        return False
    if isinstance(value, dict):
        return getattr(value, "complete", True) and all(complete(v) for v in value.values())
    if isinstance(value, list):
        return all(complete(v) for v in value)
    if isinstance(value, str):
        return "{{" not in value
    return True


def display(value):
    if isinstance(value, Unknown):
        return "{{" + value.expression[:100] + "}}"
    if isinstance(value, dict):
        return {str(k): display(v) for k, v in value.items()}
    if isinstance(value, list):
        return [display(v) for v in value]
    return value


class Syntax:
    def __init__(self, code, filename="script.js", max_nodes=250_000):
        self.code = code.encode("utf-8") if isinstance(code, str) else code
        suffix = filename.lower().split("?", 1)[0].rsplit(".", 1)[-1]
        self.tree = Parser(LANGUAGES.get(suffix, LANGUAGES["js"])).parse(self.code)
        self.nodes = []
        for node in walk(self.tree.root_node):
            self.nodes.append(node)
            if len(self.nodes) > max_nodes:
                raise ValueError(
                    f"syntax node limit reached ({max_nodes:,}); "
                    "increase --max-nodes for this bundle (uses more memory)"
                )
        self.bindings = {}
        self.imports = {}
        self.mutated = set()
        self._index()
        self.calls_by_binding = {}
        for node in self.nodes:
            if node.type == "call_expression":
                receiver = field(field(node, "function"), "object")
                if receiver and receiver.type == "identifier":
                    key = self.binding_key(text(receiver), node)
                    if key:
                        self.calls_by_binding.setdefault(key, []).append(node)

    def scope(self, node, function_only=False):
        allowed = FUNCTIONS | {"program"} if function_only else SCOPES
        while node and node.type not in allowed:
            node = node.parent
        return node or self.tree.root_node

    def scopes(self, node):
        current = node
        while current:
            if current.type in SCOPES:
                yield current
            current = current.parent

    def _bind(self, scope, name, value, declaration=None):
        key = (scope.id, name)
        self.bindings[key] = (value, declaration) if key not in self.bindings else (None, None)

    def _index(self):
        for node in self.nodes:
            if node.type == "variable_declarator":
                name = field(node, "name")
                scope = self.scope(node, node.parent.type == "variable_declaration")
                if name and name.type == "identifier":
                    self._bind(scope, text(name), field(node, "value"), node)
                elif name:
                    for part in walk(name):
                        if part.type in {"identifier", "shorthand_property_identifier_pattern"}:
                            self._bind(scope, text(part), None, node)
            elif node.type in FUNCTIONS:
                params = field(node, "parameters") or field(node, "parameter")
                if params:
                    for part in walk(params):
                        if part.type in {"identifier", "shorthand_property_identifier_pattern"}:
                            self._bind(node, text(part), None)
                name = field(node, "name")
                if name:
                    self._bind(self.scope(node.parent), text(name), None)
            elif node.type == "catch_clause":
                param = field(node, "parameter")
                if param:
                    self._bind(node, text(param), None)
            elif node.type == "import_statement":
                source = field(node, "source")
                library = literal_string(text(source)) if source else ""
                for child in node.named_children:
                    if child.type == "import_clause":
                        for part in walk(child):
                            if part.type == "identifier":
                                parent = part.parent
                                if (
                                    parent.type == "import_specifier"
                                    and field(parent, "alias")
                                    and part != field(parent, "alias")
                                ):
                                    continue
                                scope = self.scope(node)
                                self._bind(scope, text(part), None)
                                self.imports[(scope.id, text(part))] = library
        for node in self.nodes:
            if node.type in {
                "assignment_expression",
                "augmented_assignment_expression",
                "update_expression",
            }:
                left = field(node, "left") or field(node, "argument")
                root = member(left).split(".", 1)[0]
                key = self.binding_key(root, node)
                if key:
                    self.mutated.add(key)

    def binding_key(self, name, node):
        for scope in self.scopes(node):
            key = (scope.id, name)
            if key in self.bindings:
                return key
        return None

    def initializer(self, node):
        if node is None or node.type not in {"identifier", "shorthand_property_identifier"}:
            return None
        key = self.binding_key(text(node), node)
        if not key or key in self.mutated:
            return None
        value, declaration = self.bindings[key]
        if declaration is not None and declaration.end_byte > node.start_byte:
            return None
        return value

    def global_name(self, node, expected):
        name = member(node)
        return name == expected and self.binding_key(name.split(".")[0], node) is None

    def library(self, node, library):
        name = member(node)
        if not name or "." in name:
            return False
        key = self.binding_key(name, node)
        if key is None:
            return name in ({"axios"} if library == "axios" else {"$", "jQuery"})
        if key in self.mutated:
            return False
        if self.imports.get(key) == library:
            return True
        value = self.initializer(node)
        return bool(
            value
            and value.type == "call_expression"
            and member(field(value, "function")) == "require"
            and self.eval(args(value)[0] if args(value) else None) == library
        )

    def eval(self, node, depth=0):
        if node is None:
            return Unknown("unknown")
        if depth > 14 or node.has_error:
            return Unknown(text(node)[:100])

        def evaluate(n):
            return self.eval(n, depth + 1)

        kind = node.type
        if kind == "string":
            return literal_string(text(node))
        if kind == "template_string":
            parts = []
            for child in node.named_children:
                if child.type in {"string_fragment", "escape_sequence"}:
                    parts.append(literal_string('"' + text(child) + '"'))
                elif child.type == "template_substitution":
                    value = evaluate(child.named_children[0])
                    parts.append(str(display(value)))
            return "".join(parts)
        if kind == "number":
            try:
                return json.loads(text(node))
            except ValueError:
                return Unknown(text(node))
        if kind in {"true", "false", "null"}:
            return json.loads(kind)
        if kind in {"identifier", "shorthand_property_identifier"}:
            target = self.initializer(node)
            return evaluate(target) if target else Unknown(text(node))
        if kind in {
            "parenthesized_expression",
            "as_expression",
            "type_assertion",
            "non_null_expression",
            "await_expression",
        }:
            return evaluate(node.named_children[0])
        if kind == "object":
            result = Object()
            for child in node.named_children:
                if child.type == "pair":
                    key = field(child, "key")
                    name = (
                        evaluate(key)
                        if key.type in {"string", "computed_property_name"}
                        else text(key)
                    )
                    if isinstance(name, str):
                        result[name] = evaluate(field(child, "value"))
                    else:
                        result.complete = False
                elif child.type == "shorthand_property_identifier":
                    result[text(child)] = evaluate(child)
                elif child.type == "spread_element":
                    spread = evaluate(child.named_children[0])
                    if isinstance(spread, dict):
                        result.update(spread)
                        result.complete &= getattr(spread, "complete", True)
                    else:
                        # Unknown spreads can override preceding keys.
                        result = Object(complete=False)
                else:
                    result.complete = False
            return result
        if kind == "computed_property_name":
            return evaluate(node.named_children[0])
        if kind == "array":
            return [evaluate(child) for child in node.named_children]
        if kind == "binary_expression" and text(field(node, "operator")) == "+":
            left, right = evaluate(field(node, "left")), evaluate(field(node, "right"))
            if isinstance(left, str) or isinstance(right, str):
                return str(display(left)) + str(display(right))
            if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                return left + right
        if kind in {"member_expression", "subscript_expression"}:
            container = evaluate(field(node, "object"))
            key = (
                text(field(node, "property"))
                if kind == "member_expression"
                else evaluate(field(node, "index"))
            )
            if isinstance(container, dict) and isinstance(key, str) and key in container:
                return container[key]
        return Unknown(text(node)[:100])
