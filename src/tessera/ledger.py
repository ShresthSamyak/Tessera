"""The append-only audit / provenance ledger.

Every label attached, every policy decision, every escalation, every
declassification is written here as one JSON object per line (JSONL). Two jobs:

  * make human approval *meaningful* — the human sees "this action uses data
    from an untrusted web page", not a blind yes/no; and
  * make incidents forensically reconstructable — given any action, the ledger
    holds the full origin chain that led to it.

Append-only is a correctness property, not a convenience: entries are never
mutated or deleted in place. The default sink writes to a file in append mode;
an in-memory sink is provided for tests.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class LedgerEntry:
    """One immutable audit record."""

    seq: int
    timestamp: float
    session_id: str
    kind: str  # "label" | "decision" | "escalation" | "declassify" | "sanitize"
    payload: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(
            {
                "seq": self.seq,
                "timestamp": self.timestamp,
                "session_id": self.session_id,
                "kind": self.kind,
                **self.payload,
            },
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
    """Serializes audit entries to a sink with a monotonic sequence number."""

    sink: LedgerSink
    session_id: str = "default"
    _seq: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, kind: str, **payload: Any) -> LedgerEntry:
        with self._lock:
            self._seq += 1
            entry = LedgerEntry(
                seq=self._seq,
                timestamp=time.time(),
                session_id=self.session_id,
                kind=kind,
                payload=payload,
            )
            self.sink.write(entry.to_json())
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


def open_ledger(path: str | None = None, session_id: str = "default") -> Ledger:
    """Open a ledger backed by a file (or memory if ``path`` is None)."""
    sink: LedgerSink = MemorySink() if path is None else FileSink(path)
    return Ledger(sink=sink, session_id=session_id)
