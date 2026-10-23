#!/usr/bin/env python3
"""Validate the published static site's local links, fragments, and assets."""

from html.parser import HTMLParser
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1] / "site"
BASE_PATH = "/orionis/"
HOST = "stremovskyy.github.io"
REQUIRED = (
    "index.html", "api.html", "deploy.html", "security.html",
    "styles.css", "site.js", "favicon.svg",
)


class Page(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.ids = set()
        self.links = []
        self.errors = []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        identifier = attrs.get("id")
        if identifier:
            if identifier in self.ids:
                self.errors.append(f"duplicate id: {identifier}")
            self.ids.add(identifier)
        for attribute in ("href", "src"):
            if attrs.get(attribute):
                self.links.append(attrs[attribute])

    handle_startendtag = handle_starttag


def main():
    errors = [f"missing required file: {name}" for name in REQUIRED if not (ROOT / name).is_file()]
    pages = {}
    for path in sorted(ROOT.rglob("*.html")):
        page = Page(path)
        page.feed(path.read_text(encoding="utf-8"))
        pages[path.resolve()] = page
        errors.extend(f"{path.name}: {error}" for error in page.errors)

    checked = 0
    for path, page in pages.items():
        for reference in page.links:
            url = urlsplit(reference)
            if url.scheme or url.netloc:
                if url.scheme not in ("http", "https") or url.netloc != HOST:
                    continue
                if not url.path.startswith(BASE_PATH):
                    errors.append(f"{path.name}: site link is outside {BASE_PATH}: {reference}")
                    continue
                local = ROOT / unquote(url.path.removeprefix(BASE_PATH))
            elif url.path.startswith("/"):
                if not url.path.startswith(BASE_PATH):
                    errors.append(f"{path.name}: root-relative link breaks the project base path: {reference}")
                    continue
                local = ROOT / unquote(url.path.removeprefix(BASE_PATH))
            else:
                local = path.parent / unquote(url.path) if url.path else path
            if local.is_dir():
                local = local / "index.html"
            local = local.resolve()
            checked += 1
            if not local.is_relative_to(ROOT.resolve()) or not local.is_file():
                errors.append(f"{path.name}: missing local target: {reference}")
            elif url.fragment and local in pages and unquote(url.fragment) not in pages[local].ids:
                errors.append(f"{path.name}: missing fragment: {reference}")

    if errors:
        print("Static site validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"Static site OK: {len(pages)} pages, {checked} local links and resources (base {BASE_PATH}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
