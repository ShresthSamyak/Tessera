"""Integration tests against the *real* AgentDojo package.

These run only when ``agentdojo`` is installed (the optional ``[agentdojo]``
extra) and are skipped otherwise, so core CI stays dependency-light. They lock
in the binding the benchmark runner relies on: a real ``FunctionsRuntime``
classifies into the session, and the per-task ``session_factory`` isolates tasks.
No model calls are made (no API key needed).
"""

import pytest

pytest.importorskip("agentdojo")

from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from tessera.integrations.agentdojo import (
    TesseraGuard,
    TesseraRuntime,
    classify_runtime_tools,
)
from tessera.policy import PolicyEngine, Strictness
from tessera.session import Session

BENCH = "v1.2.1"


def _slack_runtime():
    return FunctionsRuntime(get_suite(BENCH, "slack").tools)


def test_real_runtime_tools_classify():
    rt = _slack_runtime()
    session = Session()
    classify_runtime_tools(session, rt)
    assert len(session.profiles) == len(rt.functions) > 0
    # The send / membership-mutating tools must be recognized as dangerous.
    assert session.profiles["send_direct_message"].is_dangerous
    assert session.profiles["remove_user_from_slack"].is_dangerous


def test_guard_session_factory_isolates_tasks():
    rt = _slack_runtime()
    guard = TesseraGuard(
        session_factory=lambda: Session(policy=PolicyEngine(Strictness.PARANOID))
    )
    _q, w1, *_ = guard.query("task one", rt)
    s1 = guard.session
    _q, w2, *_ = guard.query("task two", rt)
    s2 = guard.session
    assert isinstance(w1, TesseraRuntime) and isinstance(w2, TesseraRuntime)
    assert s1 is not s2  # a fresh, un-tainted session per task


def test_guard_query_returns_gated_runtime_and_classifies():
    rt = _slack_runtime()
    guard = TesseraGuard(session_factory=lambda: Session())
    _q, wrapped, *_ = guard.query("do the task", rt)
    assert isinstance(wrapped, TesseraRuntime)
    assert len(guard.session.profiles) == len(rt.functions)
