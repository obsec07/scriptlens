import json

import pytest

from scriptlens.analyzer import analyze
from scriptlens.security import Redactor


def review(code):
    redactor = Redactor()
    return redactor.clean(analyze(code, "app.js", redactor, "https://app.example.test/"))


@pytest.mark.parametrize(
    "code,rule",
    [
        ("const x=location.hash; document.body.innerHTML=x", "dom_html_flow"),
        ("eval(decodeURIComponent(location.search))", "dynamic_code_flow"),
        ("location.href=location.hash.slice(1)", "redirect_flow"),
        ("fetch(location.hash.slice(1))", "request_url_flow"),
        ("window.addEventListener('message',e=>{document.body.innerHTML=e.data})", "dom_html_flow"),
        ("localStorage.setItem('access_token',token)", "sensitive_browser_storage"),
        ("otherWindow.postMessage({access_token:token},'*')", "sensitive_wildcard_message"),
    ],
)
def test_review_clues_have_exact_evidence_without_vulnerability_claim(code, rule):
    findings = review(code)["findings"]
    assert rule in {f["rule"] for f in findings}
    assert all(f["status"] == "needs_review" for f in findings)
    assert all(f["evidence"]["line"] == 1 for f in findings)


@pytest.mark.parametrize(
    "code",
    [
        "document.body.innerHTML='<b>static</b>'",
        "document.body.innerHTML=DOMPurify.sanitize(location.hash)",
        "const cfg={apiKey:'AIzaPublicFirebaseConfigurationKey12345678',clientId:'public-client-id'}",
        "localStorage.setItem('theme','dark')",
        "window.addEventListener('message', e=>console.log(e.data))",
        "otherWindow.postMessage({theme:'dark'},'*')",
        "function f(location){document.body.innerHTML=location.hash}",
    ],
)
def test_ordinary_code_and_public_configuration_do_not_make_findings(code):
    assert review(code)["findings"] == []


def test_credential_format_is_redacted_in_every_field():
    fake = "ghp_" + "aB5dE7hI9kL2nO4qR6tU8wX0zC3fG5jK7mP9"
    code = (
        "const config={client_secret:"
        + json.dumps(fake)
        + "}; fetch('/api',{method:'POST',headers:{Authorization:config.client_secret},body:JSON.stringify(config)})"
    )
    result = review(code)
    assert fake not in json.dumps(result)
    assert len(result["findings"]) == 1
    assert "{{REDACTED}}" in json.dumps(result)


def test_runtime_token_stays_a_placeholder():
    result = review("fetch('/api',{headers:{Authorization:token}})")
    assert result["endpoints"][0]["headers"]["Authorization"] == "{{token}}"
    assert result["findings"] == []
