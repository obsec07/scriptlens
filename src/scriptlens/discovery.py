from html.parser import HTMLParser
from urllib.parse import urljoin


class Page(HTMLParser):
    def __init__(self, url, body):
        super().__init__(convert_charrefs=True)
        self.url = url
        self.base = url
        self.base_seen = False
        self.scripts, self.links, self.inline = [], [], []
        self.active = None
        self.feed(body)
        self.close()

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == "base" and "href" in data and not self.base_seen:
            self.base = urljoin(self.url, data["href"])
            self.base_seen = True
        if tag == "a" and data.get("href"):
            self.links.append(data["href"])
        if tag == "script":
            kind = data.get("type", "").lower().strip()
            if kind not in {
                "",
                "module",
                "text/javascript",
                "application/javascript",
                "text/ecmascript",
                "application/ecmascript",
            }:
                return
            if data.get("src"):
                self.scripts.append(data["src"])
            else:
                self.active = {"line": self.getpos()[0], "parts": []}
        if (
            tag == "link"
            and data.get("href")
            and (
                data.get("rel") == "modulepreload"
                or (data.get("rel") == "preload" and data.get("as") == "script")
            )
        ):
            self.scripts.append(data["href"])

    def handle_data(self, data):
        if self.active is not None:
            self.active["parts"].append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.active is not None:
            self.inline.append(("".join(self.active["parts"]), self.active["line"]))
            self.active = None
