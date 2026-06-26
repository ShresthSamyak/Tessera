"""AgentDojo integration — run Tessera as a defense inside AgentDojo.

`AgentDojo <https://github.com/ethz-spylab/agentdojo>`_ (Debenedetti et al., ETH
Zurich) is the standard prompt-injection benchmark for tool-using agents, and the
one CaMeL reported on. This module lets Tessera sit in an AgentDojo pipeline so
its containment can be measured against the research, apples-to-apples.

**How it binds.** AgentDojo runs tools through a ``FunctionsRuntime.run_function``
call, and a pipeline element may *replace* the runtime that flows downstream. So
the integration is two small pieces:

  * :class:`TesseraRuntime` wraps a ``FunctionsRuntime`` and overrides
    ``run_function`` — the single point every tool executes. Before execution it
    runs the Tessera flow-rule + capability gates (:meth:`Session.authorize_call`)
    and refuses dangerous, untrusted-driven calls by returning an error result
    (so the agent sees a refusal, exactly like any tool error). After a permitted
    call it ingests the result into the session (labelling + taint propagation)
    and returns the sanitized output. This is ordering-independent: it does not
    matter where in the pipeline tools run.

  * :class:`TesseraGuard` is a ``BasePipelineElement`` you insert once, early in
    the pipeline. On each turn it auto-classifies the runtime's tools into the
    session and swaps in a :class:`TesseraRuntime`, so every downstream executor
    is gated.

**Optional dependency.** ``agentdojo`` is not required to import this module — it
is only used if installed. The enforcement logic is therefore unit-testable with
a faithful mock of the runtime contract, while a real benchmark run needs
``pip install "tessera-proxy[agentdojo]"`` plus model API keys.

Example
-------
::

    from agentdojo.agent_pipeline import AgentPipeline, InitQuery, ToolsExecutionLoop, ToolsExecutor
    from tessera import Session, PolicyEngine, Strictness
    from tessera.integrations.agentdojo import TesseraGuard

    session = Session(policy=PolicyEngine(Strictness.PARANOID))
    pipeline = AgentPipeline([
        InitQuery(),
        llm,                       # your model element
        TesseraGuard(session),     # <-- classify tools + swap in the gated runtime
        ToolsExecutionLoop([ToolsExecutor(), llm]),
    ])
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

from tessera.classification import classify_tool
from tessera.policy import Decision, PolicyResult
from tessera.session import Session

# Bind to AgentDojo's BasePipelineElement when available, but degrade to a plain
# base so this module imports without the dependency (and stays mock-testable).
try:  # pragma: no cover - exercised only when agentdojo is installed
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement as _Base
except Exception:  # pragma: no cover
    _Base = object  # type: ignore[assignment, misc]


#: Optional human approver for ESCALATE decisions (AgentDojo runs unattended, so
#: the default is to deny — fail closed).
Approver = Callable[[PolicyResult], bool]


def _schema_of(function: Any) -> Optional[Mapping[str, Any]]:
    """Best-effort extraction of an MCP-style ``{"properties": {...}}`` schema.

    AgentDojo ``Function.parameters`` is a Pydantic model; its
    ``model_json_schema()`` carries the properties. Falls back to a plain mapping
    if that is what was provided (mocks/tests).
    """
    params = getattr(function, "parameters", None)
    if params is None:
        return None
    model_schema = getattr(params, "model_json_schema", None)
    if callable(model_schema):
        try:
            schema = model_schema()
        except Exception:
            return None
        return schema if isinstance(schema, Mapping) else None
    if isinstance(params, Mapping):
        return params
    return None


def classify_runtime_tools(session: Session, runtime: Any) -> None:
    """Auto-classify every tool in ``runtime`` into ``session`` (idempotent).

    Operator-set profiles already in the session are never overwritten.
    """
    functions = getattr(runtime, "functions", None) or {}
    for name, function in functions.items():
        if name in session.profiles:
            continue
        profile = classify_tool(
            str(name),
            _schema_of(function),
            description=str(getattr(function, "description", "") or ""),
        )
        session.register_tool(profile)


class TesseraRuntime:
    """Wraps an AgentDojo ``FunctionsRuntime`` and gates ``run_function``.

    Delegates every attribute to the inner runtime except ``run_function``,
    which enforces the Tessera gates and ingests results.
    """

    def __init__(
        self,
        inner: Any,
        session: Session,
        *,
        approver: Optional[Approver] = None,
        on_block: str = "error",
    ):
        # Set via __dict__ so __getattr__ delegation never recurses.
        self.__dict__["_inner"] = inner
        self.__dict__["_session"] = session
        self.__dict__["_approver"] = approver
        self.__dict__["_on_block"] = on_block

    # -- delegation ---------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(self.__dict__["_inner"], name)

    @property
    def session(self) -> Session:
        return self.__dict__["_session"]

    # -- the gated execution point -----------------------------------------

    def run_function(
        self,
        env: Any,
        function: str,
        kwargs: Mapping[str, Any],
        raise_on_error: bool = False,
    ) -> tuple[Any, Optional[str]]:
        session: Session = self.__dict__["_session"]
        inner = self.__dict__["_inner"]
        approver: Optional[Approver] = self.__dict__["_approver"]

        call_args = dict(kwargs)
        decision = session.authorize_call(str(function), call_args)

        permitted = decision.decision is Decision.ALLOW
        if not permitted and decision.decision is Decision.ESCALATE and approver:
            permitted = bool(approver(decision))

        if not permitted:
            return self._refuse(decision, env)

        # Forward the declassified (canonicalized) arguments, not the raw ones.
        if decision.cleaned_arguments:
            call_args.update(decision.cleaned_arguments)

        result, error = inner.run_function(env, function, call_args, raise_on_error)

        if error is None:
            labeled = session.ingest_result(str(function), result)
            if isinstance(result, str):
                result = labeled.content  # sanitized rendering
        return result, error

    def _refuse(self, decision: PolicyResult, env: Any = None) -> tuple[Any, str]:
        reason = f"TesseraBlocked: {decision.reason}"
        if self.__dict__["_on_block"] == "abort":
            try:  # pragma: no cover - only when agentdojo is installed
                from agentdojo.agent_pipeline.errors import AbortAgentError

                raise AbortAgentError(reason, [], env)
            except ImportError:
                pass
        return "", reason


class TesseraGuard(_Base):  # type: ignore[misc, valid-type]
    """An AgentDojo pipeline element that installs Tessera's gated runtime.

    Insert it once, after the model element and before the tools-execution loop.
    On each turn it (1) auto-classifies the runtime's tools into the session and
    (2) returns a :class:`TesseraRuntime` so all downstream tool execution is
    gated. It does not modify the query, env, or messages.

    Pass either a fixed ``session`` (taint accumulates across every call — fine
    for a single agent run) or a ``session_factory`` that mints a fresh session
    per call. A benchmark reuses one pipeline across many independent tasks, so
    it must use ``session_factory`` — otherwise one task's untrusted reads would
    taint the next.
    """

    name = "tessera_guard"

    def __init__(
        self,
        session: Optional[Session] = None,
        *,
        session_factory: Optional[Callable[[], Session]] = None,
        approver: Optional[Approver] = None,
        on_block: str = "error",
    ):
        if session is None and session_factory is None:
            session = Session()
        self.session = session
        self._session_factory = session_factory
        self._approver = approver
        self._on_block = on_block

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: Any = None,
        extra_args: Any = None,
    ) -> tuple[str, Any, Any, Any, dict]:
        # A fresh session per task when a factory is given; otherwise the fixed
        # one. (A TesseraRuntime arriving here means a prior element already
        # wrapped this turn's runtime — keep its session, stay idempotent.)
        if isinstance(runtime, TesseraRuntime):
            return (query, runtime, env, messages if messages is not None else [],
                    extra_args if extra_args is not None else {})
        session = self._session_factory() if self._session_factory else self.session
        assert session is not None
        self.session = session
        classify_runtime_tools(session, runtime)
        wrapped = TesseraRuntime(
            runtime, session, approver=self._approver, on_block=self._on_block
        )
        return (
            query,
            wrapped,
            env,
            messages if messages is not None else [],
            extra_args if extra_args is not None else {},
        )
