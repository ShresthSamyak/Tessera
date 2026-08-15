# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Tessera (`tessera-proxy` on PyPI, imported as `tessera`) is a security layer between an agent and its
tools that **contains the blast radius of a prompt injection**. It does not try to stop injections
in-band (conceded unsolvable); it enforces one rule mechanically:

> Data that originated **untrusted** may not become an argument to an **exfiltration-capable or
> irreversible** tool without passing a **declassifier** or **human approval**.

Read `README.md` for the full pitch and threat model. `SECURITY.md` is the authoritative in-scope /
out-of-scope list — it defines what the project *claims*, so a change to `sanitize.py`,
`classification.py`, `declassify.py`, or the ledger's integrity story usually needs a matching edit there.

The v0.2 "wedge" core is **pure stdlib** — keep it that way; anything needing a third-party lib goes
behind an optional extra (`[agentdojo]`, `[planner]`) and the module must still import without it.
**The floor is Python 3.10** (`requires-python`, and `pyrightconfig.json` pins `pythonVersion: "3.10"`),
so nothing from 3.11+ — no `Self`, `StrEnum`, `tomllib`, `ExceptionGroup`. Every implementation module
opens with `from __future__ import annotations` (the three `__init__.py` re-export shims don't need it),
which is what keeps `X | Y` annotations legal on 3.10.

## Commands

```bash
pip install -e ".[dev]"          # dev install (pytest is the only dev dep)
pytest                           # run the suite
pytest tests/test_policy.py      # one file
pytest tests/test_session.py -k value_flow   # one test by name substring
pytest tests/test_plan.py::test_name         # one exact test
pytest -o addopts="" -v          # verbose — see the gotcha below

pyright                          # type-check (config in pyrightconfig.json; basic mode, py.typed shipped)

tessera run --strictness balanced --ledger audit.jsonl -- python -m my_mcp_server   # the proxy
tessera bench --detail           # print the containment/utility-tax frontier table
tessera verify audit.jsonl       # check the ledger's hash chain (exit 1 = tampered)
python -m build && twine check dist/*   # package build (release flow)
```

Two things that will otherwise waste your time:

- **`pytest -v` does nothing.** `addopts = "-q"` in `pyproject.toml` is prepended to your flags, so the two
  cancel out. Use `pytest -o addopts="" -v` when you need per-test output.
- **`pyright` is not clean and is not expected to be.** It reports a standing set of errors confined to
  `tests/` and `examples/` (mostly `Ledger.sink` being typed as the `LedgerSink` protocol while tests call
  the `MemorySink`-only `.entries()`). Compare against the count before your change rather than assuming
  zero; `src/` is what should stay clean.

Runnable demos live in `examples/` and double as executable documentation of each subsystem
(`markdown_exfil_demo.py`, `declassifier_demo.py`, `declassifier_soundness_demo.py`, `plan_demo.py`,
`planner_demo.py`, `capability_demo.py`, `benchmark_demo.py`). `examples/agentdojo_bench.py` needs
`pip install ".[agentdojo]"` and an API key; `planner_demo.py` needs `pip install ".[planner]"` (the
Anthropic SDK) unless you drive it with `ScriptedPlanner` or an injected client.

## Architecture

Everything exists to feed **one decision** soundly without paralyzing the agent. The design commitment is
**"assume the model is already owned"** — guarantees never depend on the model's judgment. That forces a
two-plane split: a *trusted control plane* (plan, policy, ledger, capabilities) decides what's allowed; an
*untrusted data plane* (tool results) can only ever produce **labeled values, never actions**.

### The enforcement pipeline (the through-line across files)

Trust flows through these modules in order — to change behavior you usually touch two or three of them:

1. **`labels.py`** — the integrity lattice (Biba-style: lower = less trustworthy). `TrustLevel`
   (UNTRUSTED < UNVERIFIED < INTERNAL < TRUSTED) and `Origin`. `combine()` takes the *meet* (min). The
   policy keys off the bottom: `TrustLevel.is_untrusted` (UNTRUSTED **or** UNVERIFIED — we gate anything
   we can't positively vouch for).
2. **`classification.py`** — `classify_tool(name, schema, description)` infers a `BlastRadius`
   (reversibility, exfiltration_capable, idempotent) purely from the MCP schema. A tool is **dangerous**
   iff exfiltration-capable **or** irreversible; only dangerous tools are ever gated. `idempotent` is
   deliberately **not** part of `is_dangerous` and never reaches the flow rule — it governs *how much
   authority* a call needs, and is enforced in the capability gate (see the plan path below). The heuristic is
   deliberately **cautious**: unknown/ambiguous tools default to a reversible write, never read-only.
3. **`session.py`** — the orchestrator and the taint state. `ingest_result()` labels + taints + sanitizes
   an incoming result; `authorize_call()` / `authorize_call_labeled()` gate an outgoing call. This is where
   the strictness modes diverge (see below). **The single most important file to read.**
4. **`policy.py`** — `PolicyEngine.evaluate()` applies the flow rule given a blast radius + arg trust level,
   returning ALLOW / BLOCK / ESCALATE. Strictness does **not** change the rule; it changes how BALANCED vs
   PARANOID vs PERMISSIVE respond to untrusted-data-into-dangerous-tool.
5. **`sanitize.py`** — strips exfil channels (notably markdown-image URLs) from rendered output; runs
   inside `ingest_result`. `sanitize_value` walks containers **and typed objects** (dataclass, pydantic,
   namespace, `__slots__`) because that is what real tools return — objects are *copied, not mutated*, and
   only rebuilt when something was actually stripped. Anything it cannot inspect or rebuild is appended to
   the `unsanitized` out-list and logged as a `sanitize_gap` ledger entry, so the residual is auditable.
   None of that helps unless the call site returns `labeled.content` — see the invariant below.
6. **`ledger.py`** — append-only JSONL audit trail. Every label, sanitize, declassify, capability check,
   and decision is recorded, in logical order. Entries are **hash-chained** (`prev_hash`/`hash`, same
   construction as the capability macaroons), optionally keyed via HMAC; `verify_ledger()` /
   `tessera verify` walks the chain and reports the first break. Reopening a file **resumes** its chain,
   so a restarted proxy never starts a silent second chain. Two documented limits: an unkeyed chain can be
   recomputed wholesale, and truncation is detectable only against an externally-anchored `expected_head`.

### Two taint strategies (the crux of the utility/containment trade)

The LLM sits between a tool result and the next call and is an **untracked mixing function** — it can
launder a payload. `session.py` handles this two ways, selected by `Strictness`:

- **`PARANOID`** → *context taint*: once any untrusted value enters the session, every subsequent dangerous
  call is treated as untrusted-driven until a declassifier clears it. Sound (laundering-proof), high tax.
- **`BALANCED` / `PERMISSIVE`** → *value-flow matching*: a call is gated only if an argument's text
  literally contains a tracked untrusted token (`_significant_tokens`, min length 6). Lower tax, but
  evadable by laundering — which is exactly what declassifiers and PARANOID exist for.

### Three ways the same engine is applied

- **On the wire** — `proxy.py` (`MCPInterceptor` is pure/transport-agnostic and is what tests drive;
  `StdioProxy` wires it to a subprocess over MCP stdio JSON-RPC). Snoops `tools/list` to auto-classify;
  intercepts `tools/call`; a blocked call comes back as an in-band tool **error the agent can read**
  (never the blocked data).
- **In-process** — `sdk.py` (`protect()` / `@tool` / `Guard`). Same flow rule, same ledger, applied to
  plain callables. This is the "one line" adoption path.
- **By construction** — `plan.py` + `planner.py`. The CaMeL-style path: a `Plan` (a tiny constrained DSL:
  `plan/step/call/const/var/field`) is emitted **once from the trusted query before any untrusted data is
  seen**, then interpreted. Two stronger guarantees: (1) **structural containment** — the tool-call set is
  exactly the plan's steps, so an injection can't add a step; (2) **precise provenance** — every value's
  label is known exactly, so `authorize_call_labeled` gates only args that *actually* carry untrusted data
  (no over-tainting → lower tax at full containment; the `plan` row Pareto-dominates in `tessera bench`).
  Capabilities are **auto-derived** from constant-arg dangerous steps, and a **non-idempotent** dangerous
  step is capped at `max_uses(1)` — a step runs once, so a replay needs fresh authority. This is what stops
  an injection amplifying one planned action into fifty when the args are clean and the flow rule is silent.
  Gotcha: the capability gate runs *before* the flow rule, so a flow-rule-blocked call still spends a use
  (errs closed; pinned by `test_flow_rule_block_still_spends_the_use_budget`).

### The two membranes that let untrusted data through safely

- **`declassify.py`** — a declassifier squeezes a tainted value through a **bounded, attacker-uninfluenced**
  output space (enum member, tight pattern, typed primitive, allowlist). Registered per `(tool, arg)`.
  Anything emitting free-form attacker-derived text (a "summarize"/"rewrite") is **not** a declassifier —
  it is the laundering we defend against, and Tessera deliberately offers none. `PatternDeclassifier`
  refuses, at construction, any regex loose enough to pass an injection-probe battery — but that guard is
  *necessary, not sufficient*: soundness depends on the output space (see `test_declassifier_soundness.py`).
- **`capabilities.py`** — macaroon-style (HMAC-chained) unforgeable, attenuating grants that replace ambient
  authority. A dangerous call must pass **both** gates: a valid capability **and** the flow rule
  (see `_finalize_decision` in `session.py`).

`provenance.py` holds `LabeledValue` / `ProvenanceGraph` (the value + its label used by the plan path).
`integrations/agentdojo.py` is the `TesseraGuard` pipeline element for the AgentDojo benchmark; it imports
without the `agentdojo` dep. `eval/` holds the built-in `tessera bench` frontier harness and scenarios.

## Key invariants (don't regress these)

- **Fail closed.** Every default errs toward blocking: unknown tools classify as write-capable; unresolvable
  origins are UNVERIFIED (gated); escalation with no HITL denies.
- **Inference never *relaxes* the gate.** Name/origin inference (`_infer_origin`, `_is_read_tool`) only
  *sharpens the label* for the audit trail. The only ways a source becomes trusted are explicit
  (`trust_tool` / `set_tool_origin`) or the narrow, anti-laundering-checked action-confirmation path
  (`_is_trusted_action_confirmation` — a status/id record that re-introduces **no already-tainted token**).
  That path is the one place a *heuristic* grants trust, so it needs **two** independent guards and both
  must stay: the token-reflection check catches a payload the session has seen before, and
  `_is_status_shaped` has to bound the space for one it has **not** — every key *and* value must match
  `_STATUS_FIELD_RE` (identifier-shaped, ≤64, no whitespace / `@` / `/`). Bounding by length alone is what
  originally let a whole sentence of fresh attacker text through as a "status field". Loosening that regex
  re-opens an under-taint hole; tightening it only costs tax, so err tight.
- **Origin resolution uses `is not None`, not truthiness.** `Origin.USER_QUERY == 0` is falsy; a truthiness
  test would silently drop an explicit override. Watch this when editing `ingest_result`.
- **Every `ingest_result` call site returns `labeled.content`, never the raw result** — otherwise the
  sanitization is computed and then thrown away. This is a *call-site* rule, so it breaks silently and no
  sanitizer test catches it. It already bit `sdk.py` and `integrations/agentdojo.py`, which both guarded on
  `isinstance(result, str)` back when only strings could be sanitized; when `sanitize_value` learned to walk
  typed objects, those guards became the bug. Never reintroduce a type check on the way out.
- **The security boundary in plan mode is `parse_plan` (`planner.py`)**, not the planner. The planner (an
  LLM) is trusted only because it sees just the query + tool list; `parse_plan` is what validates its output
  into the DSL (known tools only, well-formed exprs, no use-before-bind). Treat it as the trust boundary.
- **Blocked calls surface the *reason*, never the blocked data.**

## Conventions

- **`HANDOFF.md` is the working-state context engine.** It is **git-ignored on purpose** (scratch, not a
  repo artifact) and kept as a complete self-contained context dump. **Update it after every meaningful
  change** — it is how a fresh session picks up without re-deriving. Read it first when resuming work.
- **Version lives in two places and must move in lockstep:** `pyproject.toml` `version` and
  `src/tessera/__init__.py` `__version__`. PyPI versions are immutable, so any fix re-publishes as a bump.
- **`website/` and `LAUNCH.md` are git-ignored** (marketing/drafts, not part of the package).
- New public symbols must be exported from `src/tessera/__init__.py` `__all__`.
