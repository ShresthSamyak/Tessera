"""Labeled values and the provenance graph.

A :class:`LabeledValue` is a piece of data plus the record of *where it came
from*. Values derive from other values: a tool result derives from the call
that produced it, which derived from its arguments, which may themselves have
been earlier tool results. Following those ``derived_from`` edges backward
reconstructs the full origin chain of any action — the property the audit
ledger guarantees and the HITL prompt renders.

In the v0.2 wedge the proxy cannot see inside the LLM (it is an untracked
mixing function), so propagation across a model step is handled conservatively
at the :mod:`tessera.session` layer. This module just models the values and
their explicit, observable derivations.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from tessera.labels import Origin, TrustLevel, combine_iter

_id_counter = itertools.count(1)


def _next_id(prefix: str) -> str:
    return f"{prefix}-{next(_id_counter)}"


@dataclass(frozen=True)
class ProvenanceNode:
    """One node in the origin chain of a value.

    Nodes are immutable and identified by ``node_id`` so they can be referenced
    from the ledger without copying the (possibly large) value content.
    """

    node_id: str
    origin: Origin
    level: TrustLevel
    #: Short human-readable description, e.g. "fetch_url(https://evil.test)".
    label: str
    #: IDs of the nodes this value was derived from (its inputs).
    derived_from: tuple[str, ...] = ()

    def describe(self) -> str:
        return f"{self.label} [{self.level.name}]"


@dataclass
class LabeledValue:
    """A value carrying its trust level and a pointer into the provenance graph.

    ``content`` is the actual data (typically the text of a tool result or a
    tool-call argument). ``node`` is its provenance record.
    """

    content: Any
    node: ProvenanceNode

    @property
    def level(self) -> TrustLevel:
        return self.node.level

    @property
    def is_untrusted(self) -> bool:
        return self.level.is_untrusted

    @classmethod
    def from_origin(
        cls,
        content: Any,
        origin: Origin,
        *,
        label: str | None = None,
        level: TrustLevel | None = None,
    ) -> "LabeledValue":
        """Create a fresh root value with the given origin.

        ``level`` defaults to the origin's natural level but may be overridden
        (e.g. an operator marking a specific internal tool as ``INTERNAL``).
        """
        resolved = level if level is not None else origin.default_level
        node = ProvenanceNode(
            node_id=_next_id("val"),
            origin=origin,
            level=resolved,
            label=label or origin.name.lower(),
        )
        return cls(content=content, node=node)

    def derive(
        self,
        content: Any,
        *,
        label: str,
        extra_inputs: "tuple[LabeledValue, ...]" = (),
        origin: Origin | None = None,
    ) -> "LabeledValue":
        """Produce a new value derived from this one (and any ``extra_inputs``).

        The derived value's level is the conservative combination of all
        inputs' levels — it cannot be cleaner than its dirtiest source. Use a
        declassifier (a deliberate, narrow extractor) to raise the level back
        up; ordinary derivation never can.
        """
        inputs = (self, *extra_inputs)
        level = combine_iter(v.level for v in inputs)
        node = ProvenanceNode(
            node_id=_next_id("val"),
            origin=origin if origin is not None else self.node.origin,
            level=level,
            label=label,
            derived_from=tuple(v.node.node_id for v in inputs),
        )
        return LabeledValue(content=content, node=node)

    def declassify(
        self,
        content: Any,
        *,
        label: str,
        raise_to: TrustLevel = TrustLevel.TRUSTED,
    ) -> "LabeledValue":
        """Produce a value whose trust level is *raised* above this one.

        This is the single, deliberate exception to "derivation can only lower
        trust" (see :meth:`derive`). It is sound only because the caller — a
        declassifier (:mod:`tessera.declassify`) — has constrained ``content``
        to a value drawn from a bounded, attacker-uninfluenced space, so an
        injected instruction cannot survive into the emitted value. The new
        node is attributed to the trusted control plane and keeps an edge back
        to the tainted input, so the audit chain still shows where it came from.
        """
        node = ProvenanceNode(
            node_id=_next_id("dec"),
            origin=Origin.CONTROL_PLANE,
            level=raise_to,
            label=label,
            derived_from=(self.node.node_id,),
        )
        return LabeledValue(content=content, node=node)


@dataclass
class ProvenanceGraph:
    """An index of all provenance nodes seen in a session.

    Lets the ledger and policy layer walk an action back to its roots.
    """

    nodes: dict[str, ProvenanceNode] = field(default_factory=dict)

    def add(self, value: LabeledValue) -> None:
        self.nodes[value.node.node_id] = value.node

    def chain(self, node_id: str) -> list[ProvenanceNode]:
        """Return all ancestor nodes of ``node_id`` (depth-first, deduped)."""
        seen: dict[str, ProvenanceNode] = {}
        stack = [node_id]
        while stack:
            current = stack.pop()
            node = self.nodes.get(current)
            if node is None or node.node_id in seen:
                continue
            seen[node.node_id] = node
            stack.extend(node.derived_from)
        return list(seen.values())

    def roots(self, node_id: str) -> list[ProvenanceNode]:
        """Return the source (leaf) nodes a value ultimately came from."""
        return [n for n in self.chain(node_id) if not n.derived_from]
