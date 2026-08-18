"""The append-only audit / provenance ledger.

Every label attached, every policy decision, every escalation, every
declassification is written here as one JSON object per line (JSONL). Two jobs:

  * make human approval *meaningful* — the human sees "this action uses data
    from an untrusted web page", not a blind yes/no; and
  * make incidents forensically reconstructable — given any action, the ledger
    holds the full origin chain that led to it.

Append-only is a correctness property, not a convenience: entries are never
mutated or deleted in place. But "our writer only appends" says nothing about
what happens to the file *afterwards*, so entries are **hash-chained** — each
one commits to the one before it, exactly the construction
:mod:`tessera.capabilities` uses for macaroons::

    prev_hash_0 = GENESIS_HASH
    hash_i      = H(canonical(entry_i including prev_hash_i))
    prev_hash_i = hash_{i-1}

Editing, deleting, or reordering a past entry breaks every hash after it, and
:func:`verify_ledger` reports the first break. What this does and does not buy
you — stated precisely, because an audit trail that overstates its own integrity
is worse than one that doesn't try:

  * **Unkeyed** (``H`` = SHA-256, the default): detects accidental corruption
    and any *partial* tampering. It does **not** stop an attacker who rewrites
    the file wholesale, because they can simply recompute the whole chain.
  * **Keyed** (``H`` = HMAC-SHA-256 under ``hmac_key``): forging a chain
    requires the key. This is only a real gain if the key lives somewhere the
    agent process does not — a separate collector, an HSM, an operator's
    machine. Handing the agent the key protects against nothing extra.
  * **Neither detects truncation of the tail.** Dropping the last *k* entries
    leaves a prefix that verifies perfectly. Detecting that needs an anchor held
    outside the file: record :attr:`Ledger.head` somewhere durable and pass it
    to :func:`verify_ledger` as ``expected_head``.

**Rotating the HMAC key.** :func:`verify_ledger` takes one key and applies it to
every entry -- there is no per-entry key id and no way to supply several. So the
obvious move, changing the key and continuing to append, produces a file that can
**never be verified whole again**: neither key works, and neither does unkeyed.
Turning keying *on* for an existing unkeyed file has the same effect on both
halves. Nothing stops you doing it and nothing warns you, which is why it is
called out here.

The supported procedure is a new file per key, with continuity carried outside
the chain by the anchor that already exists::

    old.head            # record this durably, before retiring the old file
    verify_ledger(old_path, hmac_key=OLD, expected_head=anchor)
    verify_ledger(new_path, hmac_key=NEW)

Each file then verifies under its own key, and the anchor still detects
truncation of the retired one.

The default sink writes to a file in append mode; an in-memory sink is provided
for tests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Protocol

#: ``prev_hash`` of the first entry in a chain (no predecessor to commit to).
GENESIS_HASH = "0" * 64

#: Top-level keys the ledger owns. Payload keys never override these — an
#: attacker-influenced value must not be able to forge an entry's own metadata.
_RESERVED_KEYS = frozenset(
    {"seq", "timestamp", "session_id", "kind", "prev_hash", "hash"}
)


def _disambiguate(payload: dict[str, Any]) -> dict[str, Any]:
    """Rename payload keys that would collide with the ledger's own fields.

    An entry is written as a flat object, so a payload key called ``hash`` or
    ``seq`` would shadow — or be shadowed by — the entry's own metadata, and the
    digest would no longer reconstruct. Renaming (rather than dropping) keeps
    the record faithful: an audit ledger must not silently lose a field.
    """
    if not any(k in _RESERVED_KEYS for k in payload):
        return payload
    return {
        (f"payload_{k}" if k in _RESERVED_KEYS else k): v for k, v in payload.items()
    }


def _canonical(body: dict[str, Any]) -> str:
    """Serialize an entry body to the exact bytes the hash commits to.

    Compact and key-sorted, so the digest depends only on the *content* of the
    entry and not on how the line happened to be formatted on disk.
    """
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(body: dict[str, Any], hmac_key: bytes | None) -> str:
    msg = _canonical(body).encode("utf-8")
    if hmac_key is None:
        return hashlib.sha256(msg).hexdigest()
    return hmac.new(hmac_key, msg, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class LedgerEntry:
    """One immutable audit record, committing to its predecessor."""

    seq: int
    timestamp: float
    session_id: str
    kind: str  # "label" | "decision" | "escalation" | "declassify" | "sanitize"
    payload: dict[str, Any]
    #: Hash of the previous entry (``GENESIS_HASH`` for the first).
    prev_hash: str = GENESIS_HASH
    #: This entry's hash over :meth:`body`. Set by :meth:`create`.
    entry_hash: str = ""

    @classmethod
    def create(
        cls,
        *,
        seq: int,
        timestamp: float,
        session_id: str,
        kind: str,
        payload: dict[str, Any],
        prev_hash: str,
        hmac_key: bytes | None = None,
    ) -> "LedgerEntry":
        """Build an entry and compute its chain hash."""
        draft = cls(
            seq=seq,
            timestamp=timestamp,
            session_id=session_id,
            kind=kind,
            payload=_disambiguate(payload),
            prev_hash=prev_hash,
        )
        return replace(draft, entry_hash=_digest(draft.body(), hmac_key))

    def body(self) -> dict[str, Any]:
        """Everything the hash commits to (i.e. the line minus ``hash``).

        Payload is spread *first* so the ledger's own fields always win: a
        payload key named ``seq`` or ``prev_hash`` can shadow nothing.
        """
        return {
            **self.payload,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "kind": self.kind,
            "prev_hash": self.prev_hash,
        }

    def to_json(self) -> str:
        return json.dumps(
            {**self.body(), "hash": self.entry_hash},
            ensure_ascii=False,
            sort_keys=True,
        )


class LedgerSink(Protocol):
    """Where ledger lines go. Implementations must be append-only."""

    def write(self, line: str) -> None: ...


@dataclass
class FileSink:
    """Append JSONL to a file, flushing every line (durable, crash-safe-ish)."""

    path: str

    def __post_init__(self) -> None:
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, exist_ok=True)

    def write(self, line: str) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())


@dataclass
class MemorySink:
    """Collect ledger lines in memory. For tests and the demo."""

    lines: list[str] = field(default_factory=list)

    def write(self, line: str) -> None:
        self.lines.append(line)

    def entries(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.lines]


@dataclass
class Ledger:
    """Serializes audit entries to a sink, hash-chained and sequence-numbered."""

    sink: LedgerSink
    session_id: str = "default"
    #: When set, entries are chained with HMAC-SHA-256 instead of bare SHA-256.
    #: Only buys tamper-*resistance* if this process is not the one holding it.
    hmac_key: bytes | None = None
    _seq: int = 0
    _prev_hash: str = GENESIS_HASH
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def head(self) -> str:
        """Hash of the most recent entry — the anchor that detects truncation.

        Persist this outside the ledger file (or ship it to a collector) and
        pass it to :func:`verify_ledger` as ``expected_head`` to prove no
        trailing entries were dropped.
        """
        return self._prev_hash

    @property
    def seq(self) -> int:
        """Sequence number of the most recent entry (0 if none written yet)."""
        return self._seq

    def record(self, kind: str, **payload: Any) -> LedgerEntry:
        with self._lock:
            self._seq += 1
            entry = LedgerEntry.create(
                seq=self._seq,
                timestamp=time.time(),
                session_id=self.session_id,
                kind=kind,
                payload=payload,
                prev_hash=self._prev_hash,
                hmac_key=self.hmac_key,
            )
            self.sink.write(entry.to_json())
            self._prev_hash = entry.entry_hash
            return entry

    # Convenience recorders -------------------------------------------------

    def label(self, tool: str, level: str, origin: str, node_id: str) -> LedgerEntry:
        return self.record(
            "label", tool=tool, level=level, origin=origin, node_id=node_id
        )

    def decision(self, result: Any) -> LedgerEntry:
        # Accepts a tessera.policy.PolicyResult without importing it (avoids a
        # cycle); reads attributes structurally.
        return self.record(
            "decision",
            tool=result.tool,
            decision=result.decision.value,
            arg_level=result.arg_level.name,
            reason=result.reason,
            provenance=list(result.provenance),
            blast_radius={
                "reversibility": result.profile.blast_radius.reversibility.name,
                "exfiltration_capable": result.profile.blast_radius.exfiltration_capable,
                "idempotent": result.profile.blast_radius.idempotent,
                "source": result.profile.source,
            },
        )

    def sanitize(self, tool: str, removed: list[str]) -> LedgerEntry:
        return self.record("sanitize", tool=tool, removed=removed)

    def sanitize_gap(self, tool: str, objects: list[str]) -> LedgerEntry:
        """Record that a result carried values the sanitizer could not defang.

        The flow rule is unaffected — the value is still labelled and gated —
        but the *rendered* channel is not closed for these, so an investigator
        should be able to see that rather than infer silence means safety.
        """
        return self.record("sanitize_gap", tool=tool, objects=objects)

    def trust_instruction(self, tokens: int) -> LedgerEntry:
        """Record that the user's own vocabulary was exempted from tracking.

        A deliberate reduction in what the session will treat as untrusted, so
        it belongs in the audit trail next to the decisions it goes on to
        affect. The token *count* is recorded rather than the tokens: the
        instruction is the user's text, and the ledger is not the place to
        copy it.
        """
        return self.record("trust_instruction", tokens=tokens)

    def task_boundary(
        self, description: str, dropped_tokens: int, level_was: str
    ) -> LedgerEntry:
        """Record that accumulated taint was deliberately dropped.

        This is the one place the session *forgets* something, so it is the one
        place an investigator most needs a marker: without it, a decision taken
        after a boundary would look as if the preceding untrusted read had never
        happened. The entry sits in the same hash chain as everything else, so a
        boundary cannot be inserted or removed after the fact.
        """
        return self.record(
            "task_boundary",
            description=description,
            dropped_tokens=dropped_tokens,
            level_was=level_was,
        )

    def declassify(
        self,
        tool: str,
        arg: str,
        declassifier: str,
        accepted: bool,
        reason: str,
        constraint: str = "",
    ) -> LedgerEntry:
        return self.record(
            "declassify",
            tool=tool,
            arg=arg,
            declassifier=declassifier,
            accepted=accepted,
            reason=reason,
            constraint=constraint,
        )

    def capability(
        self,
        tool: str,
        authorized: bool,
        reason: str,
        capability_id: str | None = None,
    ) -> LedgerEntry:
        return self.record(
            "capability",
            tool=tool,
            authorized=authorized,
            reason=reason,
            capability_id=capability_id,
        )


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LedgerVerification:
    """The result of walking a ledger's hash chain.

    Truthy iff the chain is intact, so ``if verify_ledger(path):`` reads
    naturally while the detail stays available for an operator or a report.
    """

    ok: bool
    #: Number of entries successfully verified before any break.
    entries: int
    #: Hash of the last verified entry (compare against an external anchor).
    head: str
    reason: str = "chain intact"
    #: 1-based line number where verification failed, if it did.
    broken_at_line: int | None = None
    #: ``seq`` of the offending entry, when it could be parsed.
    broken_at_seq: int | None = None

    def __bool__(self) -> bool:
        return self.ok

    def describe(self) -> str:
        if self.ok:
            # ASCII only: this goes to a console, and Windows' default cp1252
            # mangles a typographic ellipsis.
            return f"ledger intact: {self.entries} entries, head {self.head[:12]}..."
        where = f"line {self.broken_at_line}"
        if self.broken_at_seq is not None:
            where += f" (seq {self.broken_at_seq})"
        return f"ledger BROKEN at {where}: {self.reason}"


def _fail(
    entries: int, head: str, reason: str, line_no: int, seq: Any = None
) -> LedgerVerification:
    return LedgerVerification(
        ok=False,
        entries=entries,
        head=head,
        reason=reason,
        broken_at_line=line_no,
        broken_at_seq=seq if isinstance(seq, int) else None,
    )


def verify_chain(
    lines: Iterable[str],
    *,
    hmac_key: bytes | None = None,
    expected_head: str | None = None,
) -> LedgerVerification:
    """Walk a sequence of JSONL ledger lines and check the hash chain.

    Reports the *first* break, since everything after it is unverifiable
    anyway. Checks, per entry: that it parses, that it carries a ``hash``, that
    its ``prev_hash`` matches the previous entry's hash, that its ``seq`` is the
    expected next one, and that its hash recomputes over its own body.

    ``expected_head`` additionally asserts the chain ends where an external
    anchor says it should — the only way to catch a truncated tail.
    """
    prev_hash = GENESIS_HASH
    count = 0

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            return _fail(count, prev_hash, f"line is not valid JSON ({exc.msg})", line_no)
        if not isinstance(obj, dict):
            return _fail(count, prev_hash, "line is not a JSON object", line_no)

        seq = obj.get("seq")
        recorded = obj.get("hash")
        if not isinstance(recorded, str):
            return _fail(
                count,
                prev_hash,
                "entry has no 'hash' field (written by a pre-chain version?)",
                line_no,
                seq,
            )
        if obj.get("prev_hash") != prev_hash:
            return _fail(
                count,
                prev_hash,
                "prev_hash does not match the previous entry -- an entry was "
                "edited, deleted, or reordered",
                line_no,
                seq,
            )
        if seq != count + 1:
            return _fail(
                count, prev_hash, f"expected seq {count + 1}, found {seq!r}", line_no, seq
            )

        body = {k: v for k, v in obj.items() if k != "hash"}
        if not hmac.compare_digest(_digest(body, hmac_key), recorded):
            return _fail(
                count,
                prev_hash,
                "hash does not match the entry's contents -- this entry was "
                "modified after it was written"
                + ("" if hmac_key else " (or the chain was recomputed)"),
                line_no,
                seq,
            )

        prev_hash = recorded
        count += 1

    if expected_head is not None and not hmac.compare_digest(prev_hash, expected_head):
        return LedgerVerification(
            ok=False,
            entries=count,
            head=prev_hash,
            reason=(
                "chain is internally consistent but does not end at the expected "
                "head -- trailing entries were dropped"
            ),
            broken_at_line=count,
            broken_at_seq=count or None,
        )

    return LedgerVerification(ok=True, entries=count, head=prev_hash)


def verify_ledger(
    path: str,
    *,
    hmac_key: bytes | None = None,
    expected_head: str | None = None,
) -> LedgerVerification:
    """Verify a ledger file's hash chain (see :func:`verify_chain`).

    A missing file is a failure, not an empty ledger: "the audit trail isn't
    there" is precisely the case an investigator must not read as "nothing
    happened".
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return verify_chain(fh, hmac_key=hmac_key, expected_head=expected_head)
    except FileNotFoundError:
        return LedgerVerification(
            ok=False, entries=0, head=GENESIS_HASH, reason=f"no ledger file at {path!r}"
        )


def read_chain_state(path: str) -> tuple[int, str]:
    """Return ``(last_seq, head_hash)`` for an existing ledger file.

    Used to *resume* a chain when reopening a file, so a restarted proxy
    extends the existing chain instead of silently starting a second one that
    would leave a permanent unverifiable seam. A missing, empty, or
    pre-chain-format file resumes from genesis.
    """
    last: str | None = None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last = stripped
    except (FileNotFoundError, NotADirectoryError):
        return 0, GENESIS_HASH
    if last is None:
        return 0, GENESIS_HASH
    try:
        obj = json.loads(last)
    except json.JSONDecodeError:
        return 0, GENESIS_HASH
    if not isinstance(obj, dict):
        return 0, GENESIS_HASH
    head = obj.get("hash")
    seq = obj.get("seq")
    if not isinstance(head, str) or not isinstance(seq, int):
        # Legacy tail: we cannot chain onto something we can't verify, so start
        # a fresh chain. verify_ledger will flag the seam, which is the honest
        # outcome — the older prefix genuinely carries no integrity evidence.
        return 0, GENESIS_HASH
    return seq, head


def open_ledger(
    path: str | None = None,
    session_id: str = "default",
    *,
    hmac_key: bytes | None = None,
) -> Ledger:
    """Open a ledger backed by a file (or memory if ``path`` is None).

    Reopening an existing file resumes its chain (sequence number and head
    hash) so the whole file verifies as one run of entries.
    """
    if path is None:
        return Ledger(sink=MemorySink(), session_id=session_id, hmac_key=hmac_key)
    seq, head = read_chain_state(path)
    return Ledger(
        sink=FileSink(path),
        session_id=session_id,
        hmac_key=hmac_key,
        _seq=seq,
        _prev_hash=head,
    )
