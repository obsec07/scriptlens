# Contributing

Use fixtures and loopback servers for tests. New request recognizers must include
negative cases for unrelated methods, shadowed names and dynamic configuration.
Do not call a discovered endpoint, validate a credential or execute downloaded
JavaScript from the collector. Downloaded JavaScript runs only in the optional
`--dynamic` browser (dynamic.py), which must keep blocking state-changing requests,
private addresses, third-party services and out-of-scope navigation. Preserve scope checks for every redirect and the
actual DNS addresses used for connections.

Keep help and JSON plain. Only result labels may contain ANSI, and NO_COLOR/raw
must override styling. Preserve source evidence, incomplete diagnostics, body
uncertainty, credential redaction and shell quoting. Include a primary source and
coverage limits when adding a security review rule. Never assign a confirmed
vulnerability or impact based only on a pattern; `confirmed` is reserved for flows the
browser observed (marker element present in the page).

Run the lint, format, test and build commands in README.md before submitting.
