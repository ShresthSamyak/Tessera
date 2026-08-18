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

from tessera.capabilities import arg_equals, max_uses, tool_is
from tessera.classification import classify_tool
from tessera.labels import Origin, TrustLevel
from tessera.policy import Decision, PolicyResult
from tessera.provenance import LabeledValue
from tessera.session import Session

#: A tool backend actually executes a call and returns its raw result.
ToolBackend = Callable[[str, dict], Any]


class PlanError(Exception):
    """A malformed plan (unbound variable, bad field access)."""


_MISSING = object()


def _read_field(container: Any, key: str) -> Any:
    """Read field ``key`` from a structured value, returning ``_MISSING`` if absent.

    Handles the shapes real tools return: a mapping (subscript), or an object
    with attributes — e.g. a Pydantic model or dataclass, which is what
    AgentDojo tools return (``Message``). Lists/strings have no named field, so
    a name lookup on them is a miss (indexing a list of objects needs an index
    the constrained DSL doesn't yet express — a documented limitation).
    """
    if isinstance(container, Mapping):
        return container[key] if key in container else _MISSING
    if isinstance(container, (str, bytes, list, tuple, set)):
        return _MISSING
    # Object attribute access (pydantic models, dataclasses, namespaces).
    return getattr(container, key, _MISSING)


def _unevaluated(tool: str) -> PolicyResult:
    """A stand-in decision for a step the policy was never asked about.

    BLOCK rather than ALLOW: the step did not run, and every consumer of a
    :class:`StepOutcome` that only inspects ``decision`` must read it as "did
    not happen". ``StepOutcome.error`` is what distinguishes it from a genuine
    flow-rule refusal.
    """
    return PolicyResult(
        decision=Decision.BLOCK,
        tool=tool,
        arg_level=TrustLevel.UNTRUSTED,
        profile=classify_tool(tool),
        reason="step arguments could not be evaluated",
    )


class _StepEvalError(PlanError):
    """A step's arguments could not be evaluated from the current environment.

    Separate from :class:`PlanError` proper so the interpreter can tell a
    *runtime data* problem — a field that is not there, a variable whose
    producing step was refused — from a malformed program, which stays fatal.
    """


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
    #: Why this step's arguments could not be evaluated, if they could not.
    #: A step that failed here was never *offered* to the policy — it is a
    #: different outcome from "the flow rule refused it", and conflating the two
    #: would let a plan that fell over score as clean containment.
    error: str | None = None

    @property
    def allowed(self) -> bool:
        return self.executed

    @property
    def failed(self) -> bool:
        return self.error is not None


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

    @property
    def failed(self) -> list[StepOutcome]:
        """Steps whose arguments could not be evaluated.

        Check this before reading a run as containment. A plan that died on a
        bad field reference also took no dangerous action, and the two look
        identical if you only ask "did the critical call execute?".
        """
        return [o for o in self.outcomes if o.failed]


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
            try:
                labeled_args = {
                    name: self._eval(expr, env)
                    for name, expr in a_step.call.args.items()
                }
            except _StepEvalError as exc:
                # A step whose arguments cannot be evaluated fails *itself*
                # rather than aborting the plan. `parse_plan` validates
                # structure, but it cannot know the runtime shape of a tool's
                # result, so a `field` reference to a key that never
                # materializes is a data outcome, not a malformed program — and
                # a step can equally be unevaluable because the step that would
                # have bound its variable was refused.
                #
                # Continuing is no less sound: the plan's control flow is fixed
                # either way, so nothing new can run. Steps that do not depend
                # on the missing value still do, which is the whole point —
                # previously one bad reference took every later step with it.
                #
                # Note the divergence from "bind an error value": nothing is
                # bound. Binding one would let a dependent step proceed with a
                # fabricated argument (`send_email(body=<error text>)`), which
                # is worse than not running. Dependents fail in turn; only
                # independent steps carry on.
                outcomes.append(
                    StepOutcome(
                        index, a_step.call.tool, _unevaluated(a_step.call.tool),
                        False, a_step.bind, None, error=str(exc),
                    )
                )
                if self.stop_on_block:
                    break
                continue
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
                raise _StepEvalError(
                    f"variable {expr.name!r} used before it was bound"
                )
            return env[expr.name]
        if isinstance(expr, Field):
            if expr.var not in env:
                raise _StepEvalError(
                    f"variable {expr.var!r} used before it was bound"
                )
            base = env[expr.var]
            sub = _read_field(base.content, expr.key)
            if sub is _MISSING:
                raise _StepEvalError(
                    f"cannot read field {expr.key!r} of {expr.var!r} "
                    f"({type(base.content).__name__})"
                )
            # Field access preserves the parent's label (it is derived from it),
            # so an extracted string from an untrusted structure stays untrusted
            # and the flow rule gates on that label — independent of the field's
            # *content* (which may not be deep-sanitized for foreign objects).
            return base.derive(sub, label=f"{expr.var}.{expr.key}")
        raise PlanError(f"unknown expression type: {expr!r}")

    # -- capability auto-derivation ----------------------------------------

    def _derive_capabilities(self, the_plan: Plan) -> None:
        """Mint least authority for the plan: one grant per dangerous step.

        A plan step executes exactly once, so a grant that authorizes unlimited
        calls is broader than the plan needs. Bounding it is where the
        :attr:`~tessera.classification.BlastRadius.idempotent` axis earns its
        keep: repeating a *non-idempotent* tool causes **additional effect**, so
        its grant is capped at a single use — an injection that induces the same
        planned call fifty times finds authority for one. An idempotent tool is
        left uncapped, because by definition the repeat changes nothing (and a
        cap would only add retry friction with no containment gain).
        """
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
            if not profile.blast_radius.idempotent:
                # One grant per step, so N identical steps still get N uses.
                caveats.append(max_uses(1))
            self.session.grant(engine.mint(*caveats))
