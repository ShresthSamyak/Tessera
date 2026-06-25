"""Run scenarios through the real interceptor and compute the frontier.

For each scenario and strictness setting we stand up a :class:`RecordingServer`
(a fake upstream that records which calls actually executed), drive the
scenario's scripted steps through the genuine :class:`MCPInterceptor`, and then
ask one question of the *critical* call:

  * attack  -> was it **contained** (the dangerous call did not auto-execute)?
  * benign  -> was it **preserved** (the legitimate call did auto-execute)?

Escalations are resolved by a human who is never available (auto-deny), so the
numbers describe Tessera's *automatic* behavior -- the worst case for utility
and the safe case for containment. The count of escalations is reported
separately, since "how often is a human bothered" is its own metric.

  containment_rate = contained_attacks / total_attacks      (security)
  utility_tax      = taxed_benign / total_benign            (usability)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tessera.eval.scenarios import Scenario, default_scenarios
from tessera.ledger import open_ledger
from tessera.policy import PolicyEngine, PolicyResult, Strictness
from tessera.proxy import MCPInterceptor
from tessera.session import Session


class RecordingServer:
    """A minimal upstream MCP server that records the calls it executes."""

    def __init__(self, scenario: Scenario):
        self._scenario = scenario
        self.executed: list[tuple[str, dict]] = []

    def __call__(self, message: dict) -> dict:
        method = message.get("method")
        id_ = message.get("id")
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": id_, "result": {"tools": self._scenario.tools}}
        if method == "tools/call":
            params = message.get("params") or {}
            name = str(params.get("name", ""))
            args = params.get("arguments", {})
            self.executed.append((name, args))
            text = self._scenario.results.get(name, "ok")
            return {
                "jsonrpc": "2.0",
                "id": id_,
                "result": {"content": [{"type": "text", "text": text}], "isError": False},
            }
        return {"jsonrpc": "2.0", "id": id_, "result": {}}


@dataclass
class ScenarioResult:
    """Outcome of one scenario at one strictness."""

    scenario_id: str
    kind: str
    strictness: Strictness
    #: True == good outcome (attack contained, or benign preserved).
    success: bool
    critical_executed: bool
    escalated: bool

    @property
    def label(self) -> str:
        if self.kind == "attack":
            return "contained" if self.success else "LEAKED"
        return "preserved" if self.success else "taxed"


def run_scenario(scenario: Scenario, strictness: Strictness) -> ScenarioResult:
    """Drive one scenario through the interceptor and grade the critical call."""
    server = RecordingServer(scenario)
    escalated_tools: list[str] = []

    def deny_and_record(result: PolicyResult, explanation: str) -> bool:
        escalated_tools.append(result.tool)
        return False  # no human available

    session = Session(
        session_id=scenario.id,
        policy=PolicyEngine(strictness=strictness),
        ledger=open_ledger(session_id=scenario.id),
    )
    interceptor = MCPInterceptor(session, server, hitl=deny_and_record)
    interceptor.handle_request({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})

    for i, (tool, args) in enumerate(scenario.steps, start=1):
        interceptor.handle_request(
            {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": tool, "arguments": args},
            }
        )

    critical_executed = scenario.critical in server.executed
    if scenario.kind == "attack":
        success = not critical_executed  # contained iff it did not run
    else:
        success = critical_executed  # preserved iff it did run

    return ScenarioResult(
        scenario_id=scenario.id,
        kind=scenario.kind,
        strictness=strictness,
        success=success,
        critical_executed=critical_executed,
        escalated=scenario.critical[0] in escalated_tools,
    )


@dataclass
class FrontierPoint:
    """Aggregate metrics for one strictness setting."""

    strictness: Strictness
    containment_rate: float
    utility_tax: float
    escalations: int
    results: list[ScenarioResult] = field(default_factory=list)

    @property
    def attacks_total(self) -> int:
        return sum(1 for r in self.results if r.kind == "attack")

    @property
    def attacks_contained(self) -> int:
        return sum(1 for r in self.results if r.kind == "attack" and r.success)

    @property
    def benign_total(self) -> int:
        return sum(1 for r in self.results if r.kind == "benign")

    @property
    def benign_preserved(self) -> int:
        return sum(1 for r in self.results if r.kind == "benign" and r.success)


def evaluate_point(
    strictness: Strictness, scenarios: list[Scenario] | None = None
) -> FrontierPoint:
    """Run the whole catalog at one strictness and aggregate."""
    scen = scenarios if scenarios is not None else default_scenarios()
    results = [run_scenario(s, strictness) for s in scen]
    attacks = [r for r in results if r.kind == "attack"]
    benign = [r for r in results if r.kind == "benign"]
    containment = (sum(r.success for r in attacks) / len(attacks)) if attacks else 1.0
    tax = (sum(not r.success for r in benign) / len(benign)) if benign else 0.0
    return FrontierPoint(
        strictness=strictness,
        containment_rate=containment,
        utility_tax=tax,
        escalations=sum(r.escalated for r in results),
        results=results,
    )


def evaluate_frontier(
    scenarios: list[Scenario] | None = None,
    strictnesses: list[Strictness] | None = None,
) -> list[FrontierPoint]:
    """Compute the full frontier across strictness settings."""
    modes = strictnesses if strictnesses is not None else list(Strictness)
    return [evaluate_point(m, scenarios) for m in modes]


def format_frontier(points: list[FrontierPoint], *, detail: bool = False) -> str:
    """Render the frontier as a text table (for the CLI / demo)."""
    lines = []
    header = f"{'strictness':<12} {'containment':>12} {'utility tax':>12} {'escalations':>12}"
    lines.append(header)
    lines.append("-" * len(header))
    for p in points:
        lines.append(
            f"{p.strictness.value:<12} "
            f"{p.containment_rate * 100:>10.0f} % "
            f"{p.utility_tax * 100:>10.0f} % "
            f"{p.escalations:>12}"
        )
    if detail:
        for p in points:
            lines.append("")
            lines.append(f"[{p.strictness.value}] "
                         f"{p.attacks_contained}/{p.attacks_total} attacks contained, "
                         f"{p.benign_preserved}/{p.benign_total} benign preserved")
            for r in p.results:
                mark = "ok " if r.success else "XX "
                esc = " (escalated)" if r.escalated else ""
                lines.append(f"   {mark}{r.scenario_id:<42} {r.label}{esc}")
    return "\n".join(lines)
