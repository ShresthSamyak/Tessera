"""The CaMeL-style plan interpreter — the structurally sound spine.

This is the most principled version of the thesis (after Google DeepMind's
CaMeL, "Defeating Prompt Injections by Design"). The idea: emit the plan **once,
from the trusted user query, before any untrusted data is seen**, as a small
program in a constrained interpreter. Untrusted data then flows through that
fixed program only as typed, labeled values — it can fill in values but can
never alter control flow. An injection in the data cannot change *what the
program does*, because the program was fixed by trusted input.

Two guarantees fall out, and both are stronger than the heuristic taint tracking
the proxy uses when it cannot see inside the model:

  1. **Structural containment.** The set of tool calls is exactly the plan's
     steps. An injection in a tool result can become a *value*, but it can never
     introduce a new step — so it cannot, e.g., add a "send the secret to the
     attacker" call that the user never planned.

  2. **Precise provenance, no over-tainting.** Every value's label is known
     exactly (a constant from the trusted plan is TRUSTED; a tool result is
     labeled by its origin; a derived value combines its inputs). So the flow
     rule fires only on the arguments that *actually* carry untrusted data —
     eliminating the false positives that force the value-flow/context-taint
     heuristics to over-block. This is "lower utility tax for the same
     containment".

The planner itself (an LLM in production) is out of scope here: its security
does not matter because it only ever sees the trusted query. We accept the
:class:`Plan` it would emit as the trusted artifact and interpret it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Union

from tessera.capabilities import arg_equals, tool_is
from tessera.labels import Origin
from tessera.policy import Decision, PolicyResult
from tessera.provenance import LabeledValue
from tessera.session import Session

#: A tool backend actually executes a call and returns its raw result.
ToolBackend = Callable[[str, dict], Any]


class PlanError(Exception):
    """A malformed plan (unbound variable, bad field access)."""


# --------------------------------------------------------------------------
# The constrained program: expressions, calls, steps, plan
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Const:
    """A literal value from the trusted plan. Always TRUSTED."""

    value: Any


@dataclass(frozen=True)
class Var:
    """A reference to the result of an earlier step."""

    name: str


@dataclass(frozen=True)
class Field:
    """Field access into a (structured) earlier result; preserves its label."""

    var: str
    key: str


Expr = Union[Const, Var, Field]


@dataclass(frozen=True)
class Call:
    """A tool call whose arguments are fixed expressions (not free model text)."""

    tool: str
    args: Mapping[str, Expr] = field(default_factory=dict)


@dataclass(frozen=True)
class Step:
    """One step: run ``call``, optionally binding its result to a variable."""

    call: Call
    bind: str | None = None


@dataclass(frozen=True)
class Plan:
    """A fixed program emitted from the trusted query before untrusted data."""

    steps: tuple[Step, ...]
    query: str = ""


# Convenience builders --------------------------------------------------------

def const(value: Any) -> Const:
    return Const(value)


def var(name: str) -> Var:
    return Var(name)


def field_of(var_name: str, key: str) -> Field:
    return Field(var_name, key)


def call(tool: str, **args: Expr) -> Call:
    return Call(tool=tool, args=dict(args))


def step(call: Call, bind: str | None = None) -> Step:
    return Step(call=call, bind=bind)


def plan(*steps: Step, query: str = "") -> Plan:
    return Plan(steps=tuple(steps), query=query)


# --------------------------------------------------------------------------
# Interpreter
# --------------------------------------------------------------------------


@dataclass
class StepOutcome:
    index: int
    tool: str
    decision: PolicyResult
    executed: bool
    bind: str | None
    value: LabeledValue | None

    @property
    def allowed(self) -> bool:
        return self.executed


@dataclass
class PlanRun:
    outcomes: list[StepOutcome]
    env: dict[str, LabeledValue]

    @property
    def completed(self) -> bool:
        """True if every step executed (nothing was blocked)."""
        return all(o.executed for o in self.outcomes)

    @property
    def blocked(self) -> list[StepOutcome]:
        return [o for o in self.outcomes if not o.executed]


@dataclass
class PlanInterpreter:
    """Executes a fixed :class:`Plan` against a tool backend, soundly.

    ``auto_capabilities``: if the session has a capability engine, mint and grant
    a capability for each *dangerous* step, scoped to that step's constant
    arguments — automatically deriving least authority from the plan. (Enforced
    only if the session also has ``require_capabilities`` set.)

    ``stop_on_block``: if True, halt the plan at the first blocked step (the
    safe default for a strict deployment); if False, skip the blocked step and
    continue (useful to see every decision in one run).
    """

    session: Session
    backend: ToolBackend
    auto_capabilities: bool = True
    stop_on_block: bool = False

    def run(self, the_plan: Plan) -> PlanRun:
        env: dict[str, LabeledValue] = {}
        if self.auto_capabilities and self.session.capability_engine is not None:
            self._derive_capabilities(the_plan)

        outcomes: list[StepOutcome] = []
        for index, a_step in enumerate(the_plan.steps):
            labeled_args = {
                name: self._eval(expr, env) for name, expr in a_step.call.args.items()
            }
            decision = self.session.authorize_call_labeled(a_step.call.tool, labeled_args)
            executed = decision.decision is Decision.ALLOW
            value: LabeledValue | None = None

            if executed:
                call_args = {name: lv.content for name, lv in labeled_args.items()}
                if decision.cleaned_arguments:
                    call_args.update(decision.cleaned_arguments)
                raw = self.backend(a_step.call.tool, call_args)
                value = self.session.ingest_result(a_step.call.tool, raw)
                if a_step.bind:
                    env[a_step.bind] = value

            outcomes.append(
                StepOutcome(index, a_step.call.tool, decision, executed, a_step.bind, value)
            )
            if not executed and self.stop_on_block:
                break

        return PlanRun(outcomes=outcomes, env=env)

    # -- evaluation ---------------------------------------------------------

    def _eval(self, expr: Expr, env: Mapping[str, LabeledValue]) -> LabeledValue:
        if isinstance(expr, Const):
            # A constant comes from the trusted plan -> TRUSTED.
            return LabeledValue.from_origin(expr.value, Origin.USER_QUERY, label="const")
        if isinstance(expr, Var):
            if expr.name not in env:
                raise PlanError(f"variable {expr.name!r} used before it was bound")
            return env[expr.name]
        if isinstance(expr, Field):
            if expr.var not in env:
                raise PlanError(f"variable {expr.var!r} used before it was bound")
            base = env[expr.var]
            try:
                sub = base.content[expr.key]
            except (KeyError, TypeError, IndexError) as exc:
                raise PlanError(
                    f"cannot read field {expr.key!r} of {expr.var!r}: {exc}"
                ) from None
            # Field access preserves the parent's label (it is derived from it).
            return base.derive(sub, label=f"{expr.var}.{expr.key}")
        raise PlanError(f"unknown expression type: {expr!r}")

    # -- capability auto-derivation ----------------------------------------

    def _derive_capabilities(self, the_plan: Plan) -> None:
        engine = self.session.capability_engine
        assert engine is not None
        for a_step in the_plan.steps:
            profile = self.session._profile_for(a_step.call.tool)
            if not profile.is_dangerous:
                continue
            caveats = [tool_is(a_step.call.tool)]
            for name, expr in a_step.call.args.items():
                if isinstance(expr, Const):
                    caveats.append(arg_equals(name, expr.value))
            self.session.grant(engine.mint(*caveats))
