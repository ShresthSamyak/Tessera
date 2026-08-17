# Security Policy

Tessera is a security tool, so its own threat surface matters. This document is
the responsible-disclosure path and -- just as important for this project -- a
precise statement of *what counts as a vulnerability*, because Tessera's whole
design draws a sharp line between the two.

## Reporting a vulnerability

**Please do not open a public issue for a suspected vulnerability.** Use a
private channel:

1. **Preferred:** GitHub Private Vulnerability Reporting --
   [open a report](https://github.com/ShresthSamyak/Tessera/security/advisories/new)
   (Security -> "Report a vulnerability"). This keeps the report private until a
   fix is coordinated.
2. **Fallback:** email the maintainer at **shresthsamyak@gmail.com** with
   `[tessera-security]` in the subject. If you want to send encrypted, say so and
   we will exchange keys first.

Please include, as much as you can:

- the version (`pip show tessera-proxy`) or commit,
- the strictness mode / configuration (this is decisive -- see scope below),
- a minimal reproduction: the tool definitions, the plan or call sequence, and
  the untrusted input,
- what you expected the flow rule to do, and what happened instead,
- the impact (what got exfiltrated or executed).

A failing test against `tests/` is the gold standard and the fastest path to a
fix.

## What is in scope

Tessera makes exactly one claim:

> Untrusted-origin data may not become an argument to an exfiltration-capable or
> irreversible tool without passing a declassifier or human approval.

A vulnerability is **a way to break that containment guarantee.** Concretely,
in scope:

- **Containment bypass.** Untrusted-origin data reaching an exfiltration-capable
  or irreversible tool argument without a declassifier or approval, in a mode
  that claims soundness (`paranoid`, or the plan interpreter).
- **Taint-laundering to a trusted label.** Any path that relabels
  untrusted data as trusted without an explicit operator `trust_tool` /
  declassifier -- e.g. an action tool whose confirmation echoes attacker content
  back as "trusted" (the class fixed in the action-confirmation soundness work).
  This covers attacker content appearing for the **first** time in a status
  field, not only content the session has already seen: an action tool's result
  is promoted only when every key and value is identifier-shaped (no
  whitespace, no `@`, no `/`, at most 64 characters), so free-form prose in a
  status field is a reportable bug. The **documented limit**: an
  identifier-shaped string can still be attacker-influenced -- a
  server-generated slug derived from an attacker-supplied title. Shape is a
  utility-tax heuristic, not a soundness mechanism, and `paranoid` / plan mode
  do not rely on it at all. A report that prose, an address, a URL, or a long
  value was promoted is in scope; "a 30-character attacker-chosen slug was
  promoted" is the known boundary.
- **Declassifier soundness failure.** A built-in declassifier whose output space
  is actually attacker-influenced (i.e. it launders), or a bypass of the
  construction-time probe guard.
- **Capability forgery or attenuation escape.** Minting or amplifying authority
  without the root key, or using a capability beyond its caveats.
- **Plan-interpreter / `parse_plan` escape.** Causing the interpreter to execute
  a step not present in the validated plan, or `parse_plan` accepting a plan that
  references unknown tools, dangling variables, or otherwise smuggles control
  flow.
- **Unlabelled ingestion.** Tool-result data reaching the agent without being
  labelled, tainted and recorded. The stdio proxy ingests the **whole** result
  object, so every shape the MCP spec allows is covered — `structuredContent`,
  an embedded `resource`'s text, a `resource_link`'s description, a bare-string
  `content`, and the JSON-RPC `error` object — not only `content[].text`. A
  result shape that reaches the agent with no `label` entry in the ledger is in
  scope. Known limit: content the proxy *forwards without awaiting*, i.e.
  server-initiated notifications used for streaming partial results, is not
  ingested.
- **Output-sanitizer bypass.** An exfiltration channel (e.g. markdown image)
  that survives sanitization. This covers strings nested inside containers and
  inside typed objects (dataclasses, Pydantic models, namespaces, `__slots__`
  classes), which are walked and rebuilt. The documented limit: a value whose
  fields cannot be read or whose type cannot be reconstructed passes through --
  that is recorded as a `sanitize_gap` ledger entry rather than being silent, so
  a report of "the sanitizer missed X" is in scope, but "an unreadable C type
  passed through and was logged as such" is the known boundary.
- **Audit-ledger integrity.** Tampering with, or forging entries in, the
  append-only ledger such that a gated decision is not faithfully recorded.
  Entries are hash-chained and checked by `tessera verify`; a mutation that
  leaves the chain verifying is in scope. The documented limits are **not**:
  rewriting an *unkeyed* chain end-to-end (use `--ledger-key-env`, with the
  verifier's key held off the agent host), and dropping trailing entries
  (detectable only against an externally-recorded `--expected-head`).

## What is out of scope (by design, not by omission)

These are not vulnerabilities -- they are documented, deliberate boundaries of
the threat model. Claiming otherwise is the over-promising Tessera exists to
avoid.

- **The model obeying an injected instruction.** Tessera does **not** prevent
  prompt injection in-band -- that is conceded as unsolvable. A report that "the
  LLM followed the injection" is expected behavior. It only becomes a
  vulnerability if the resulting dangerous action *actually executed* on
  untrusted data (i.e. a containment bypass, above).
- **Exfiltration of a *provenance-clean* secret in a value-flow mode.** The
  flow rule is an integrity rule -- untrusted data must not drive a dangerous
  tool. When an injection supplies only the *intent* and the secret itself
  comes from a trusted source (a vetted config store, a secret manager), the
  argument contains no untrusted token, so `balanced` / `permissive` allow the
  call. The letter of the guarantee holds and the intuition it creates does
  not, so it is stated here rather than left implied: under value-flow,
  containment of that shape is coincidental, and re-wording the payload is
  enough to lose it. `paranoid` and the plan interpreter both contain it, and
  `Session(exfil_requires_clean_context=True)` closes it inside the value-flow
  modes at a measured cost in utility tax. A report that `balanced` allowed
  this is expected; the same against `paranoid`, plan mode, or with that flag
  set, is in scope.
- **Laundering past `balanced` / `permissive`.** These modes use value-flow
  matching and are explicitly **not** laundering-proof -- a payload paraphrased
  through the model can evade them. This is the documented trade for lower
  utility tax; `paranoid` and the plan interpreter are the sound modes. A
  laundering evasion of `balanced` is expected; the same evasion of `paranoid`
  is in scope.
- **Fragment reuse from a script written without spaces.** Value-flow matching
  segments on whitespace, which is all the standard library offers. Content in
  CJK or Thai therefore tokenizes into clause-sized runs: a secret republished
  as part of the run it appeared in **is** caught, but one lifted out of the
  middle of an unspaced run is not, because no token boundary exists there.
  Segmenting properly needs a real tokenizer, which the pure-stdlib constraint
  rules out. `paranoid` and plan mode do not tokenize and are unaffected. A
  non-ASCII secret republished verbatim from a whitespace-delimited source *is*
  in scope, and is tested across Latin, Japanese, Cyrillic, Arabic and Thai.
- **Short all-letter secrets in value-flow modes.** `balanced` / `permissive`
  track a token by length (6+) or by secret-*shape* (4+ characters, all digits
  or letters-and-digits mixed -- so OTPs, PINs, short ids and key fragments are
  tracked). A secret that is both **shorter than 6 characters and pure
  letters** is indistinguishable from ordinary prose by shape, and tracking it
  would gate on any argument quoting a common word. That one is a known
  residual of value-flow mode, not a bug -- use `paranoid` or plan mode, whose
  containment does not depend on token matching at all. A short **numeric or
  alphanumeric** secret flowing unflagged *is* in scope.
- **Covert channels via tool timing or side effects.** Acknowledged residual
  risk, documented in the README's scope section.
- **`begin_task()` called while the agent's context carries over.** The call
  drops accumulated taint deliberately, and is sound only at a boundary where
  the *model's* context restarts too. If the conversation continues across it,
  an injection read before the boundary is still in the model's context after
  it, and clearing the session's memory of it is laundering. Only the
  integrator can know whether the precondition holds, which is why the call is
  explicit and never automatic; every boundary is recorded as a
  `task_boundary` ledger entry so an investigator can see exactly where taint
  was dropped. Using it across a continuous conversation is operator error. A
  way to trigger it *without* the operator asking — say a tool result that
  causes a reset — would be a vulnerability.
- **Misconfiguration.** Marking an attacker-reachable source as
  `trust_tool(...)`, or writing a semantically-loose declassifier (e.g. a regex
  that accepts any email address), is operator error, not a Tessera bug. We do
  try to make the safe path the default and the unsafe path loud.
- The marketing website, dependency CVEs without a demonstrated impact on
  Tessera, and standard non-issues (DoS, missing security headers, social
  engineering, physical access).

## Supported versions

Tessera is **alpha** and pre-1.0. Only the latest published version receives
security fixes.

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Response expectations

This is currently a small, single-maintainer project, so timelines are honest
rather than aspirational:

- **Acknowledgement:** within 3 business days.
- **Initial assessment** (in scope? severity?): within ~10 days.
- **Fix:** targeted by severity; a confirmed containment bypass is treated as
  highest priority because it breaks the one claim. PyPI versions are immutable,
  so a fix ships as a new release.

We follow coordinated disclosure: we will agree a disclosure date with you,
credit you in the advisory and release notes unless you prefer to remain
anonymous, and publish a clear writeup -- including, where relevant, the
regression test that now guards the fix.

## Safe harbor

We will not pursue or support legal action against good-faith security research
that respects this policy: testing only against your own deployments, avoiding
privacy violations and service disruption, and giving us a reasonable chance to
remediate before public disclosure. Thank you for helping keep Tessera honest.
