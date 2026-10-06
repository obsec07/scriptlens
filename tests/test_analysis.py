import json
import shlex

import pytest

from scriptlens.analyzer import analyze
from scriptlens.security import Redactor

SOURCE = "https://cdn.example.test/assets/app.js"
PAGE = "https://app.example.test/dashboard/"


def inspect(code, page=PAGE, source=SOURCE):
    redactor = Redactor()
    return redactor.clean(analyze(code, source, redactor, page))


def endpoint(code, **kwargs):
    values = inspect(code, **kwargs)["endpoints"]
    assert len(values) == 1
    return values[0]


def test_fetch_post_body_headers_source_and_curl():
    item = endpoint(
        """const api='/api'; fetch(api+'/users', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email:user.email, role:'member'})});"""
    )
    assert item["method"] == "POST"
    assert item["url"] == "https://app.example.test/api/users"
    assert item["body"]["value"] == {"email": "{{user.email}}", "role": "member"}
    assert item["body"]["complete"] is False
    argv = shlex.split(item["curl"])
    assert json.loads(argv[argv.index("--data-raw") + 1]) == item["body"]["value"]
    assert item["evidence"][0]["source"] == SOURCE
    assert item["execution"] == "not_sent"


@pytest.mark.parametrize("client", ["axios", "client"])
def test_axios_base_url_keeps_api_prefix_with_leading_slash(client):
    prefix = "const client=axios.create({baseURL:'/api/v2'});" if client == "client" else ""
    item = endpoint(prefix + f"{client}.post('/users', {{name}}, {{baseURL:'/api/v2'}});")
    assert item["url"] == "https://app.example.test/api/v2/users"
    assert item["headers"]["Content-Type"] == "application/json"


def test_imported_axios_alias_and_call_config():
    item = endpoint("import req from 'axios'; req({url:'/save',method:'patch',data:{active:true}})")
    assert item["method"] == "PATCH"
    assert item["body"]["value"] == {"active": True}


def test_template_url_and_dynamic_body():
    item = endpoint("fetch(`/users/${id}`, {method:'POST',body:JSON.stringify({id})})")
    assert item["url"].endswith("/users/{{id}}")
    assert "--globoff" in item["curl"]
    assert item["body"]["complete"] is False


def test_direct_js_has_unknown_document_base():
    item = endpoint("fetch('/api/users')", page=None)
    assert item["url"] is None
    assert item["url_template"] == "{{BASE_URL}}/api/users"
    assert "cdn.example.test" not in item["curl"]


@pytest.mark.parametrize(
    "code",
    [
        "// fetch('/fake')\nconst text=\"fetch('/fake')\";",
        "const m=new Map(); m.get('/fake');",
        "const fetch=(u)=>u; fetch('/fake');",
        "function f(fetch){ fetch('/fake'); }",
        "function f(axios){ axios.post('/fake'); }",
        "const axios={get(x){return x;}}; axios.get('/fake');",
        "const paths=['/api/admin','/admin','/assets/logo.svg'];",
    ],
)
def test_do_not_invent_endpoints_from_unrelated_code(code):
    assert inspect(code)["endpoints"] == []


def test_mutable_binding_does_not_reuse_stale_url():
    result = inspect("let url='/old'; url=getURL(); fetch(url);")
    assert result["endpoints"] == []
    assert len(result["unresolved_requests"]) == 1


def test_unknown_options_do_not_invent_get():
    item = endpoint("fetch('/api', options)")
    assert item["method"] is None
    assert item["curl"] is None


def test_spread_can_override_method():
    item = endpoint("fetch('/api', {method:'POST', ...options})")
    assert item["method"] is None


def test_nested_scope_does_not_reuse_other_function_url():
    result = inspect("function a(){const url='/a';fetch(url)} function b(){fetch(url)}")
    assert [r["url"] for r in result["endpoints"]] == ["https://app.example.test/a"]
    assert len(result["unresolved_requests"]) == 1


def test_xhr_header_body_pairing():
    item = endpoint(
        "const r=new XMLHttpRequest();r.open('POST','/upload');r.setRequestHeader('X-Test','yes');r.send(JSON.stringify({name}));"
    )
    assert item["method"] == "POST"
    assert item["headers"] == {"X-Test": "yes"}
    assert item["body"]["value"] == {"name": "{{name}}"}


def test_jquery_get_params_are_not_a_post_body():
    item = endpoint("$.get('/search',{q:'abc'})")
    assert item["url"] == "https://app.example.test/search?q=abc"
    assert item["body"]["kind"] == "none"


def test_urlencoded_body_and_beacon():
    item = endpoint("navigator.sendBeacon('/events',new URLSearchParams({event:'open'}))")
    assert item["method"] == "POST"
    assert item["body"]["kind"] == "urlencoded"
    assert "event=open" in item["curl"]


@pytest.mark.parametrize("constructor,method", [("WebSocket", "WEBSOCKET"), ("EventSource", "SSE")])
def test_streaming_endpoints_do_not_get_fake_http_curl(constructor, method):
    item = endpoint(f"new {constructor}('/events')")
    assert item["method"] == method
    assert item["curl"] is None


def test_shell_quoted_curl_has_no_command_substitution():
    url = "https://api.example.test/x?input=$(touch /tmp/scriptlens-nope)"
    item = endpoint("fetch(" + json.dumps(url) + ")")
    assert shlex.split(item["curl"])[-1] == url
    assert "'" in item["curl"]


def test_graphql_body_and_tagged_operation():
    result = inspect(
        """const q=gql`query User($id: ID!) {user(id:$id){name}}`; fetch('/graphql',{method:'POST',body:JSON.stringify({query:'mutation Save($name:String!){save(name:$name){id}}',variables:{name}})});"""
    )
    assert len(result["graphql_operations"]) == 2
    assert result["graphql_operations"][0]["variables"] == ["id"]
    assert result["graphql_operations"][1]["endpoint"] == "https://app.example.test/graphql"


def test_typescript_and_jsx():
    item = endpoint(
        "const path: string='/api'; fetch(path); const x=<div>hello</div>;", source="app.tsx"
    )
    assert item["url"] == "https://app.example.test/api"


def test_dependencies_only_from_syntax_not_random_strings():
    result = inspect(
        "import './one.js'; import('./two.js'); const x='./not-a-script.js'; // # sourceMappingURL=app.js.map"
    )
    assert result["dependencies"] == ["./one.js", "./two.js"]
    assert result["source_maps"] == ["app.js.map"]


def test_escaped_string_literal():
    item = endpoint(r"""fetch('\x2fapi\u002fusers')""")
    assert item["url"] == "https://app.example.test/api/users"


def test_formdata_keeps_field_names_and_text_curl_placeholders():
    item = endpoint(
        "const form=new FormData();form.append('caption','hello');form.append('file',file);fetch('/upload',{method:'POST',body:form})"
    )
    assert item["body"]["value"] == {"caption": "hello", "file": "{{file}}"}
    assert "--form-string" in item["curl"]
    assert "file={{file}}" in item["curl"]


def test_urlsearchparams_appends_are_recovered():
    item = endpoint(
        "const params=new URLSearchParams();params.append('name',name);fetch('/form',{method:'POST',body:params})"
    )
    assert item["body"]["value"] == {"name": "{{name}}"}


def test_url_constructor_uses_actual_document_origin():
    item = endpoint("fetch(new URL('/api',location.origin))")
    assert item["url"] == "https://app.example.test/api"


def test_axios_instance_headers_survive_per_request_headers():
    item = endpoint(
        "const api=axios.create({headers:{'X-Base':'yes'}});api.get('/api',{headers:{'X-Request':'ok'}})"
    )
    assert item["headers"] == {"X-Base": "yes", "X-Request": "ok"}


def test_duplicate_query_parameters_survive_in_json():
    item = endpoint("fetch('/api?id=1&id=2')")
    assert item["query_parameters"] == [{"name": "id", "value": "1"}, {"name": "id", "value": "2"}]
