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


def _load_bench():
    import importlib.util
    import pathlib

    spec = importlib.util.spec_from_file_location(
        "agentdojo_bench",
        pathlib.Path(__file__).resolve().parents[1] / "examples" / "agentdojo_bench.py",
    )
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    return bench


def test_plan_dsl_coverage_boundary():
    # The deliberate coverage boundary for Option B: which tasks the constrained
    # DSL expresses without iteration/indexing. Pins the measured numbers so a
    # DSL/classifier change that shifts coverage is caught.
    bench = _load_bench()
    exp, allids = bench.expressible_user_tasks(get_suite(BENCH, "slack"))
    assert len(allids) == 21 and len(exp) == 3      # iteration-heavy suite
    exp_t, all_t = bench.expressible_user_tasks(get_suite(BENCH, "travel"))
    assert len(all_t) == 20 and len(exp_t) == 16    # mostly straight-line
    # expressible ids are a real subset, and stable
    assert set(exp).issubset(set(allids))


def test_plan_mode_harness_contains_with_oracle_planner():
    """Validate the Option-B harness end-to-end WITHOUT API keys, using an oracle
    planner that returns each task's ground-truth as a const-only plan. Confirms
    injection + interpreter execution + grading all run, and that plan mode
    *contains* the attack (ASR 0) — the publishable containment property. Utility
    is intentionally NOT asserted high: plan mode emits no text answer, so
    Q&A-graded tasks fail by construction (a known confound, see HANDOFF)."""
    from tessera.plan import call, const, plan as mkplan, step
    from tessera.policy import PolicyEngine, Strictness
    from tessera.session import Session

    bench = _load_bench()
    ad = bench._import_agentdojo()
    suite = get_suite(BENCH, "travel")

    class OraclePlanner:  # returns ground-truth as a const plan (perfect planner)
        def __init__(self, suite):
            self._env = suite.load_and_inject_default_environment({})
            self._by_prompt = {ut.PROMPT: ut for ut in suite.user_tasks.values()}

        def plan(self, prompt, specs):
            ut = self._by_prompt[prompt]
            steps = [
                step(call(fc.function, **{k: const(v) for k, v in fc.args.items()}))
                for fc in ut.ground_truth(self._env)
            ]
            return mkplan(*steps)

    expressible, _ = bench.expressible_user_tasks(suite)
    user_ids = expressible[:3]
    inj_ids = list(suite.injection_tasks.keys())[:2]
    sf = lambda: Session(policy=PolicyEngine(Strictness.PARANOID))  # noqa: E731
    util, asr, coverage, n = bench.evaluate_plan(
        ad, suite, "important_instructions", "gpt-4o-mini-2024-07-18",
        OraclePlanner(suite), sf, user_ids, inj_ids,
    )
    assert n == len(user_ids) * len(inj_ids)
    assert coverage == 1.0          # oracle always emits a valid plan
    assert asr == 0.0               # plan mode contains the attack (the claim)
    assert 0.0 <= util <= 1.0       # measurable; not asserted high (no answer synth)
