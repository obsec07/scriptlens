# Research notes

Reviewed 2026-10-06. This tool uses static observations to organize authorized
research. It does not reproduce the full analysis frameworks in the papers and
never presents a source-code match as an exploit proof.

## Sources and implementation choices

1. **OWASP WSTG: Review Web Page Content for Information Leakage**
   [Article](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage/)
   identifies client-side code, embedded sensitive values and source maps as
   useful review surfaces. ScriptLens discovers declared maps and analyzes their
   embedded originals. Map availability alone is not a security finding.

2. **JAW: Studying Client-side CSRF with Hybrid Property Graphs and Declarative Traversals**,
   Soheil Khodayari and Giancarlo Pellegrino, USENIX Security 2021.
   [Paper and abstract](https://www.usenix.org/conference/usenixsecurity21/presentation/khodayari)
   [PDF](https://www.usenix.org/system/files/sec21-khodayari.pdf)
   studies attacker-influenced client requests using a combination of static and
   dynamic information. It motivates recording request templates and potential
   input-to-request flows. ScriptLens implements only a bounded local static
   approximation: it does not build JAW's hybrid graphs or claim its validation
   coverage, measured accuracy, or exploit confirmation.

3. **How the Web Tangled Itself: Uncovering the History of Client-Side Web (In)Security**,
   Ben Stock, Martin Johns, Marius Steffens and Michael Backes, USENIX Security 2017.
   [Paper](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-stock.pdf),
   especially sections 4.1–4.2. The study distinguishes potentially dangerous
   flows from validated exploits and explains why missing postMessage-origin
   checks alone do not establish a vulnerability. ScriptLens does not label all
   message listeners as insecure; it surfaces relevant local flows or sensitive
   fields sent with a wildcard target for manual review.

4. **PortSwigger: DOM-based vulnerabilities and controlling the web-message source**
   [DOM sources and sinks](https://portswigger.net/web-security/dom-based)
   [Web messages](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source)
   explain how controllable inputs reach security-relevant browser operations.
   ScriptLens follows direct expressions and simple local constants into selected
   sinks. Guards, callback reachability, sanitizers and exploit impact still need
   browser-based confirmation. Known sanitizer calls are not treated as transparent
   copies of their input.

5. **Firebase: Learn about and manage API keys**
   [Official guidance](https://firebase.google.com/docs/projects/api-keys)
   explains that Firebase client keys identify projects and are often public by
   design, while authorization is enforced elsewhere. ScriptLens does not turn
   a generic `apiKey` or Firebase configuration into a credential finding.

6. **Fetch and Axios request semantics**
   [MDN Fetch guide](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch)
   [Axios request configuration](https://axios-http.com/docs/req_config)
   inform method defaults, request data, headers and Axios base-URL handling.
   Unknown/spread configuration does not receive an invented GET method. Relative
   browser request paths resolve against the document context; Axios base prefixes
   are preserved when reconstructing ordinary instance calls. Curl output is a
   template because cookies, interceptors and runtime serialization may differ.

7. **Tree-sitter Python bindings**
   [Official project](https://github.com/tree-sitter/py-tree-sitter)
   provides the parser interface used with official JavaScript and TypeScript
   grammars. Parsing actual call nodes avoids treating comments, documentation
   strings, arbitrary `.get()` methods and unrelated path literals as API calls.
   Parser recovery is retained as an explicit incomplete-analysis diagnostic.

## What a researcher should inspect next

| Observed clue | Follow-up within authorized scope | What it does not prove |
| --- | --- | --- |
| IDs or tenant fields in an API call | Compare access using two controlled users/tenants | IDOR/BOLA from a path alone |
| Admin/internal endpoint or client role flags | Check server enforcement with permitted accounts | An authorization bypass merely because a route exists |
| POST/PUT/PATCH/DELETE bodies | Understand accepted fields, authentication, CSRF and server validation | That every field is writable or a CSRF attack works |
| GraphQL operations and variables | Review requested fields and field-level authorization | Introspection access or unauthorized data exposure |
| Token or private-key format | Determine whether it is real, active and appropriately restricted | Credential validity, privileges or impact |
| URL/message input reaches HTML or code | Trace sanitizers/guards and confirm a controlled browser effect | Executable XSS from a static flow alone |
| URL input affects a request or navigation | Review origin constraints and runtime behavior | A working client-side CSRF or open redirect |
| Sensitive browser storage or wildcard messaging | Identify the actual data and which contexts can access it | A leak solely from use of the API |
| Source maps, comments and debug configuration | Inspect original code for meaningful sensitive material | A bounty-valid issue from a map, internal hostname or TODO alone |
| Third-party libraries and client-only controls | Establish exact versions/configuration and reachable behavior | A dependency CVE or business-logic flaw from naming alone |

The last row and broad business-logic review are manual follow-ups, not implemented
vulnerability detectors. The tool deliberately avoids guessed CVEs, arbitrary
"hidden endpoint" strings, automatic credential checks and severity inflation.

## Evidence and failure handling

Every request links to source URL/path, line, column and a short redacted snippet.
Downloads and local files include hashes. Distinct request shapes remain separate;
identical shapes collect multiple source locations. Unsupported dynamic requests,
blocked scope, source-map limitations, download limits and parse errors are kept
in JSON. No source-map filename is used as a filesystem path or fetched as an
original source URL. Embedded originals are analyzed in memory.
