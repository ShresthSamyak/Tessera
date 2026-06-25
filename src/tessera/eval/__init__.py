"""Tessera's evaluation harness.

A security product cannot be judged on one number -- any system blocks all
attacks by blocking everything. The whole game is *containment without breaking
legitimate work*, so Tessera is measured on a **frontier**: attack-containment
rate against utility tax, plotted across policy-strictness settings.

This package provides a deterministic, reproducible harness:

  * :mod:`tessera.eval.scenarios` -- a catalog of injection attacks (the four
    the charter names) and benign workflows, each a fixed sequence of tool
    interactions, so runs are repeatable without any LLM in the loop;
  * :mod:`tessera.eval.harness` -- runs each scenario through the real
    interceptor at a given strictness and computes the frontier.

The point is not a high score; it is the honest curve. ``balanced`` value-flow
matching catches literal exfiltration cheaply but is evaded by laundering;
``paranoid`` context-taint catches laundering at a real utility cost. The
harness makes that tradeoff visible and measurable -- which is the whole pitch.
"""

from tessera.eval.harness import (
    FrontierPoint,
    ScenarioResult,
    evaluate_frontier,
    evaluate_plan_point,
    run_scenario,
    run_scenario_plan,
)
from tessera.eval.scenarios import CATALOG, Scenario, default_scenarios

__all__ = [
    "CATALOG",
    "FrontierPoint",
    "Scenario",
    "ScenarioResult",
    "default_scenarios",
    "evaluate_frontier",
    "evaluate_plan_point",
    "run_scenario",
    "run_scenario_plan",
]
