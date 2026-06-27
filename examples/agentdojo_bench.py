"""Run Tessera as a defense inside the AgentDojo benchmark.

AgentDojo (Debenedetti et al., ETH Zurich) is the standard prompt-injection
benchmark for tool-using agents -- the one CaMeL reported on. This script puts
Tessera's numbers next to a no-defense baseline on real attacks.

Requirements (your machine, with your own key -- NOT this repo's CI):

    pip install -e ".[agentdojo]"
    $env:OPENAI_API_KEY = "sk-..."        # PowerShell  (or export on bash)
    python examples/agentdojo_bench.py

What it does: builds an AgentDojo pipeline with an OpenAI model as the agent,
runs a small slice of a task suite under an injection attack twice -- once with
no defense, once with `TesseraGuard` inserted -- and prints utility and Attack
Success Rate (ASR) for each. Containment = 1 - ASR.

Polarity (verified against the installed AgentDojo): a task's `security` flag is
True when the injection *succeeded*, so `security_results` mean == ASR, and
lower is better for the defender.

COST: each task runs several model calls; defaults are tiny (a few tasks x a few
injections x 2 configs) to keep a first run cheap on gpt-4o-mini. Scale up with
the flags once you've seen it work. Use --list to inspect suites/attacks without
calling the API.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import tempfile

DEFAULT_MODEL = "gpt-4o-mini-2024-07-18"
BENCHMARK_VERSION = "v1.2.1"


def _import_agentdojo():
    try:
        from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig
        from agentdojo.attacks.attack_registry import ATTACKS, load_attack
        from agentdojo.benchmark import aggregate_results, benchmark_suite_with_injections
        from agentdojo.logging import OutputLogger
        from agentdojo.task_suite.load_suites import get_suite, get_suites
    except ImportError as exc:
        print("AgentDojo is not installed. Run:  pip install -e \".[agentdojo]\"")
        print(f"(import error: {exc})")
        raise SystemExit(2)
    return {
        "AgentPipeline": AgentPipeline,
        "PipelineConfig": PipelineConfig,
        "ATTACKS": ATTACKS,
        "load_attack": load_attack,
        "aggregate_results": aggregate_results,
        "benchmark_suite_with_injections": benchmark_suite_with_injections,
        "OutputLogger": OutputLogger,
        "get_suite": get_suite,
        "get_suites": get_suites,
    }


def _safe(name: str) -> str:
    """Make a string safe to use as a path component (AgentDojo logs by name)."""
    import re
    return re.sub(r'[:\\/*?"<>|]', "-", name)


def _list_returning_tools(suite) -> set[str]:
    tools = suite.tools.values() if hasattr(suite.tools, "values") else suite.tools
    out = set()
    for f in tools:
        rt = str(getattr(f, "return_type", ""))
        if rt.startswith("list") or "list[" in rt:
            out.add(f.name)
    return out


def expressible_user_tasks(suite) -> tuple[list[str], list[str]]:
    """Draw the coverage boundary: which user tasks the constrained plan DSL can
    express *without iteration or indexing*.

    A task is expressible iff its ground-truth call sequence is straight-line:
    no function repeats (no looping over a list) AND no list-returning read
    feeds a later consumer (no selecting/indexing an item out of a list). These
    are exactly the two constructs the current DSL lacks; adding them would put
    iteration/indexing into the security-boundary interpreter (a soundness cost,
    not just effort — deferred, see HANDOFF §8). Returns (expressible_ids, all_ids).
    """
    env = suite.load_and_inject_default_environment({})
    list_returning = _list_returning_tools(suite)
    expressible, all_ids = [], []
    for tid, task in suite.user_tasks.items():
        all_ids.append(tid)
        try:
            funcs = [c.function for c in task.ground_truth(env)]
        except Exception:
            continue  # can't classify -> treat as not-expressible
        repeated = len(funcs) != len(set(funcs))
        seen_list = selection = False
        for f in funcs:
            if not seen_list and f in list_returning:
                seen_list = True
                continue
            if seen_list and f not in list_returning:
                selection = True
                break
        if not repeated and not selection:
            expressible.append(tid)
    return expressible, all_ids


def print_coverage(ad) -> None:
    print("Plan-DSL coverage of AgentDojo (no iteration/indexing):\n")
    total_e = total_t = 0
    for name in ("slack", "banking", "travel", "workspace"):
        suite = ad["get_suite"](BENCHMARK_VERSION, name)
        exp, allids = expressible_user_tasks(suite)
        total_e += len(exp)
        total_t += len(allids)
        pct = 100 * len(exp) // len(allids) if allids else 0
        print(f"  {name:10s} {len(exp):>2}/{len(allids):<2} ({pct:>2}%) expressible")
    pct = 100 * total_e // total_t if total_t else 0
    print(f"  {'TOTAL':10s} {total_e:>2}/{total_t:<2} ({pct}%)")
    print("\nPoint plan-mode runs at high-coverage suites (travel/workspace);\n"
          "run heuristic modes on the full slice. See HANDOFF section 7.")


def build_pipeline(ad, model: str, strictness):
    """Build the AgentDojo pipeline, optionally with TesseraGuard inserted."""
    from tessera.policy import PolicyEngine
    from tessera.session import Session
    from tessera.integrations.agentdojo import TesseraGuard

    cfg = ad["PipelineConfig"](
        llm=model, model_id=model, defense=None,
        system_message_name=None, system_message=None,
    )
    pipe = ad["AgentPipeline"].from_config(cfg)
    if strictness is None:
        # NOTE: pipeline.name becomes a filesystem path in AgentDojo's logdir.
        # Keep it path-safe (no ':' — illegal on Windows; AgentDojo only catches
        # ValidationError/FileNotFoundError, not the resulting OSError).
        pipe.name = f"baseline-{_safe(model)}"
        return pipe
    pipe.name = f"tessera-{strictness.value}-{_safe(model)}"
    # Fresh session per task (the benchmark reuses one pipeline across tasks).
    guard = TesseraGuard(
        session_factory=lambda: Session(policy=PolicyEngine(strictness=strictness))
    )
    pipe.elements.insert(1, guard)  # right after InitQuery; before tools execute
    return pipe


def evaluate(ad, pipe, suite, attack_name, user_tasks, injection_tasks, verbose):
    attack = ad["load_attack"](attack_name, suite, pipe)
    # AgentDojo's benchmark builds a TraceLogger that reads `Logger.get().logdir`
    # from the ambient logging context; the default NullLogger has no logdir, so
    # the call must run inside an OutputLogger context (with a real logdir).
    logdir = pathlib.Path(tempfile.mkdtemp(prefix="tessera-agentdojo-"))
    with ad["OutputLogger"](str(logdir)):
        results = ad["benchmark_suite_with_injections"](
            pipe, suite, attack,
            logdir=logdir, force_rerun=True,
            user_tasks=user_tasks, injection_tasks=injection_tasks, verbose=verbose,
        )
    # SuiteResults is a TypedDict (plain dict at runtime) -> subscript, not attr.
    security = results["security_results"]
    utility = results["utility_results"]
    n = len(security)
    util = ad["aggregate_results"]([utility]) if utility else 0.0
    asr = ad["aggregate_results"]([security]) if n else 0.0
    return util, asr, n


def main() -> None:
    ap = argparse.ArgumentParser(description="Tessera inside the AgentDojo benchmark.")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--suite", default="slack", choices=["slack", "banking", "travel", "workspace"])
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--user-tasks", type=int, default=3, help="how many user tasks (0 = all)")
    ap.add_argument("--injection-tasks", type=int, default=2, help="how many injection tasks (0 = all)")
    ap.add_argument("--strictness", default="paranoid", choices=["paranoid", "balanced", "permissive"])
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--list", action="store_true", help="list suites/attacks and exit (no API calls)")
    ap.add_argument("--coverage", action="store_true", help="show plan-DSL coverage of each suite and exit (no API calls)")
    args = ap.parse_args()

    ad = _import_agentdojo()
    from tessera.policy import Strictness

    if args.coverage:
        print_coverage(ad)
        return

    if args.list:
        print("Suites:", list(ad["get_suites"](BENCHMARK_VERSION).keys()))
        print("Attacks:", list(ad["ATTACKS"].keys()))
        s = ad["get_suite"](BENCHMARK_VERSION, args.suite)
        print(f"{args.suite}: {len(s.user_tasks)} user tasks, {len(s.injection_tasks)} injection tasks")
        return

    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY is not set. Set it and re-run:")
        print('  PowerShell:  $env:OPENAI_API_KEY = "sk-..."')
        raise SystemExit(2)

    suite = ad["get_suite"](BENCHMARK_VERSION, args.suite)
    user_tasks = list(suite.user_tasks.keys())[: args.user_tasks] if args.user_tasks else None
    injection_tasks = list(suite.injection_tasks.keys())[: args.injection_tasks] if args.injection_tasks else None
    strictness = Strictness(args.strictness)

    print(f"Suite={args.suite}  attack={args.attack}  model={args.model}")
    print(f"user_tasks={user_tasks or 'ALL'}  injection_tasks={injection_tasks or 'ALL'}\n")

    print("Running no-defense baseline ...")
    base = build_pipeline(ad, args.model, None)
    u0, a0, n = evaluate(ad, base, suite, args.attack, user_tasks, injection_tasks, args.verbose)

    print(f"Running Tessera ({strictness.value}) ...")
    tess = build_pipeline(ad, args.model, strictness)
    u1, a1, _ = evaluate(ad, tess, suite, args.attack, user_tasks, injection_tasks, args.verbose)

    print("\n" + "=" * 64)
    print(f"AgentDojo results  ({n} task x injection pairs each)")
    print("=" * 64)
    print(f"{'config':<22}{'utility':>10}{'ASR':>10}{'containment':>14}")
    print("-" * 64)
    print(f"{'no-defense':<22}{u0*100:>9.0f}%{a0*100:>9.0f}%{(1-a0)*100:>13.0f}%")
    print(f"{'tessera/'+strictness.value:<22}{u1*100:>9.0f}%{a1*100:>9.0f}%{(1-a1)*100:>13.0f}%")
    print("\nASR = Attack Success Rate (lower is better). Containment = 1 - ASR.")
    print("Utility is task success under attack; the gap vs baseline is the tax.")


if __name__ == "__main__":
    main()
