"""Tests for the trusted planner and, crucially, its DSL validator.

The validator (`parse_plan`) is the trusted-control-plane boundary: it must turn
*any* JSON into either a well-formed constrained plan or an error — never
arbitrary execution. The ClaudePlanner tests use a fake client so the whole
prompt/parse path is covered without the `anthropic` package or an API key.
"""

import pytest

from tessera.plan import Const, Field, Var
from tessera.planner import (
    ClaudePlanner,
    PlannerError,
    ScriptedPlanner,
    ToolSpec,
    parse_plan,
    plan_to_dict,
)

TOOLS = [
    {"name": "read_doc", "inputSchema": {"properties": {"doc_id": {}}}},
    {"name": "send_email", "inputSchema": {"properties": {"to": {}, "subject": {}, "body": {}}}},
]
ALLOWED = {"read_doc", "send_email"}

GOOD = {
    "steps": [
        {"bind": "doc", "tool": "read_doc", "args": {"doc_id": {"const": "q3"}}},
        {"tool": "send_email", "args": {"to": {"const": "me@co"}, "body": {"var": "doc"}}},
    ]
}


# --- happy path ------------------------------------------------------------

def test_parse_valid_plan_and_roundtrip():
    p = parse_plan(GOOD, allowed_tools=ALLOWED, query="do it")
    assert p.query == "do it"
    assert len(p.steps) == 2
    assert p.steps[0].bind == "doc"
    assert isinstance(p.steps[0].call.args["doc_id"], Const)
    assert isinstance(p.steps[1].call.args["body"], Var)
    assert plan_to_dict(p) == GOOD


def test_parse_accepts_json_string():
    import json
    p = parse_plan(json.dumps(GOOD), allowed_tools=ALLOWED)
    assert len(p.steps) == 2


def test_field_expression():
    data = {"steps": [
        {"bind": "doc", "tool": "read_doc", "args": {"doc_id": {"const": "x"}}},
        {"tool": "send_email", "args": {"body": {"field": {"var": "doc", "key": "summary"}}}},
    ]}
    p = parse_plan(data, allowed_tools=ALLOWED)
    expr = p.steps[1].call.args["body"]
    assert isinstance(expr, Field) and expr.var == "doc" and expr.key == "summary"


# --- red-team: the validator must reject malformed / unsafe plans ----------

@pytest.mark.parametrize("bad", [
    "not even json {{{",
    {"no_steps": 1},
    {"steps": "nope"},
    {"steps": [42]},
    {"steps": [{"args": {}}]},                                  # missing tool
    {"steps": [{"tool": "", "args": {}}]},                      # empty tool
    {"steps": [{"tool": "send_email", "args": "x"}]},           # args not object
])
def test_reject_structurally_malformed(bad):
    with pytest.raises(PlannerError):
        parse_plan(bad, allowed_tools=ALLOWED)


def test_reject_unknown_tool():
    with pytest.raises(PlannerError):
        parse_plan({"steps": [{"tool": "delete_everything", "args": {}}]}, allowed_tools=ALLOWED)


def test_reject_forward_variable_reference():
    bad = {"steps": [{"tool": "send_email", "args": {"body": {"var": "doc"}}}]}
    with pytest.raises(PlannerError):
        parse_plan(bad, allowed_tools=ALLOWED)


def test_reject_forward_field_reference():
    bad = {"steps": [{"tool": "send_email", "args": {"body": {"field": {"var": "doc", "key": "x"}}}}]}
    with pytest.raises(PlannerError):
        parse_plan(bad, allowed_tools=ALLOWED)


@pytest.mark.parametrize("expr", [
    {"const": "x", "var": "y"},        # two keys
    {"unknown": "x"},                   # not a recognized expr
    {"field": {"var": "doc"}},          # field missing key
    {"field": ["doc", "k"]},            # field not an object
    "literal-not-wrapped",              # bare value, not an expr object
])
def test_reject_malformed_expressions(expr):
    bad = {"steps": [
        {"bind": "doc", "tool": "read_doc", "args": {"doc_id": {"const": "q"}}},
        {"tool": "send_email", "args": {"body": expr}},
    ]}
    with pytest.raises(PlannerError):
        parse_plan(bad, allowed_tools=ALLOWED)


def test_reject_bad_bind_identifier():
    bad = {"steps": [{"bind": "not an identifier", "tool": "read_doc", "args": {}}]}
    with pytest.raises(PlannerError):
        parse_plan(bad, allowed_tools=ALLOWED)


def test_no_allowlist_permits_any_tool_name():
    # When allowed_tools is None, tool names aren't constrained (the interpreter
    # still classifies + gates them) — but structure is still validated.
    p = parse_plan({"steps": [{"tool": "whatever", "args": {}}]})
    assert p.steps[0].call.tool == "whatever"


# --- ToolSpec --------------------------------------------------------------

def test_toolspec_from_mcp():
    spec = ToolSpec.from_mcp(TOOLS[1])
    assert spec.name == "send_email"
    assert set(spec.params) == {"to", "subject", "body"}


# --- ScriptedPlanner -------------------------------------------------------

def test_scripted_planner_validates_against_offered_tools():
    planner = ScriptedPlanner({"steps": [{"tool": "wire_money", "args": {}}]})
    with pytest.raises(PlannerError):
        planner.plan("pay rent", TOOLS)  # wire_money wasn't offered


def test_scripted_planner_returns_plan():
    p = ScriptedPlanner(GOOD).plan("do it", TOOLS)
    assert len(p.steps) == 2


# --- ClaudePlanner with a fake client --------------------------------------

class _Block:
    def __init__(self, input):
        self.type = "tool_use"
        self.name = "emit_plan"
        self.input = input


class _Resp:
    def __init__(self, input, stop_reason="tool_use", blocks=None):
        self.content = blocks if blocks is not None else [_Block(input)]
        self.stop_reason = stop_reason


class _FakeMessages:
    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._resp


class FakeClient:
    def __init__(self, resp):
        self.messages = _FakeMessages(resp)


def test_claude_planner_parses_and_forces_tool():
    client = FakeClient(_Resp(GOOD))
    p = ClaudePlanner(client=client).plan("read the doc and email me", TOOLS)
    assert len(p.steps) == 2
    sent = client.messages.calls[0]
    assert sent["tool_choice"] == {"type": "tool", "name": "emit_plan"}
    assert sent["model"] == "claude-opus-4-8"
    assert any(t["name"] == "emit_plan" for t in sent["tools"])


def test_claude_planner_validates_model_output_against_allowlist():
    # The model "emits" a tool that was never offered — the validator catches it
    # even though it came from the (trusted) planner.
    client = FakeClient(_Resp({"steps": [{"tool": "exfiltrate", "args": {}}]}))
    with pytest.raises(PlannerError):
        ClaudePlanner(client=client).plan("summarize", TOOLS)


def test_claude_planner_raises_on_refusal():
    client = FakeClient(_Resp(None, stop_reason="refusal", blocks=[]))
    with pytest.raises(PlannerError):
        ClaudePlanner(client=client).plan("do something", TOOLS)


def test_claude_planner_raises_when_no_tool_call():
    client = FakeClient(_Resp(None, blocks=[]))  # model returned no emit_plan block
    with pytest.raises(PlannerError):
        ClaudePlanner(client=client).plan("do something", TOOLS)


# --- parse_plan enforces the field-key rule too ----------------------------

def test_parse_plan_refuses_a_private_field_key():
    """The trust boundary must refuse what the interpreter also refuses."""
    import pytest

    from tessera.planner import PlannerError, parse_plan

    def build(key):
        return {"steps": [
            {"tool": "read_doc", "bind": "d", "args": {"doc_id": {"const": "q"}}},
            {"tool": "search_docs",
             "args": {"query": {"field": {"var": "d", "key": key}}}},
        ]}

    allowed = {"read_doc", "search_docs"}
    # A public dotted path is fine...
    parse_plan(build("labels.severity"), allowed_tools=allowed)
    # ...anything reaching internals is not.
    for bad in ("__class__", "__class__.__init__.__globals__", "a._b"):
        with pytest.raises(PlannerError, match="field key"):
            parse_plan(build(bad), allowed_tools=allowed)
