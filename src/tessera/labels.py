"""Trust labels and the security lattice.

Every piece of data that flows through Tessera carries a :class:`TrustLevel`
describing its *integrity* — how much we trust where it came from. These levels
form a lattice; combining two values takes the most conservative (lowest) of
their levels, because data is only as trustworthy as its least trustworthy
input.

This is an *integrity* lattice (à la Biba), not a confidentiality one: lower =
less trustworthy = more dangerous to act on. The central policy
(:mod:`tessera.policy`) keys off the bottom of this lattice — ``UNTRUSTED``.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Iterable


class TrustLevel(IntEnum):
    """How much we trust the *origin* of a value.

    Ordered from least to most trustworthy. The numeric values matter only for
    the ordering; never serialize them as integers across versions — use the
    name.
    """

    #: Read from an attacker-reachable surface: a fetched web page, inbound
    #: email body, an arbitrary uploaded document, or any tool output that can
    #: carry attacker-controlled text. This is the bottom of the lattice and
    #: the trigger for the flow rule.
    UNTRUSTED = 0

    #: Origin unknown or only partially vetted. Treated conservatively — for
    #: policy purposes this is as dangerous as UNTRUSTED, but kept distinct so
    #: the ledger can tell "we know this is hostile" from "we don't know".
    UNVERIFIED = 1

    #: A vetted internal system the operator has declared trustworthy (an
    #: internal database, a first-party service). Not attacker-controlled.
    INTERNAL = 2

    #: The user's own typed query, or a value minted by Tessera's trusted
    #: control plane. The top of the lattice.
    TRUSTED = 3

    @property
    def is_untrusted(self) -> bool:
        """True if acting on this data should be gated by the flow rule.

        Both ``UNTRUSTED`` and ``UNVERIFIED`` count: we gate anything we cannot
        positively vouch for, which is the sound (conservative) choice.
        """
        return self <= TrustLevel.UNVERIFIED

    @property
    def is_trusted(self) -> bool:
        """True if this data is safe to feed to a dangerous tool unescorted."""
        return self >= TrustLevel.INTERNAL


def combine(*levels: TrustLevel) -> TrustLevel:
    """Combine trust levels of inputs that flow into one derived value.

    Returns the lattice *meet* (the minimum), because a value derived from
    several sources is only as trustworthy as its least trustworthy input.
    Combining nothing yields ``TRUSTED`` (the identity / top element).

    >>> combine(TrustLevel.TRUSTED, TrustLevel.UNTRUSTED)
    <TrustLevel.UNTRUSTED: 0>
    >>> combine()
    <TrustLevel.TRUSTED: 3>
    """
    result = TrustLevel.TRUSTED
    for level in levels:
        if level < result:
            result = level
    return result


def combine_iter(levels: Iterable[TrustLevel]) -> TrustLevel:
    """Like :func:`combine`, but takes an iterable."""
    return combine(*levels)


class Origin(IntEnum):
    """Why a value carries the trust level it does.

    Recorded alongside the level so the ledger and HITL prompts can explain a
    decision in human terms ("this argument came from a fetched web page")
    rather than just showing a bare label.
    """

    USER_QUERY = 0  # the human's own typed instruction -> TRUSTED
    CONTROL_PLANE = 1  # minted by Tessera itself -> TRUSTED
    VETTED_SYSTEM = 2  # operator-declared internal system -> INTERNAL
    TOOL_OUTPUT = 3  # generic tool result, origin depends on the tool
    WEB_CONTENT = 4  # fetched page / search result -> UNTRUSTED
    INBOUND_MESSAGE = 5  # email / chat from a third party -> UNTRUSTED
    DOCUMENT = 6  # arbitrary uploaded / shared document -> UNTRUSTED
    UNKNOWN = 7  # cannot determine -> UNVERIFIED

    @property
    def default_level(self) -> TrustLevel:
        """The trust level this origin maps to absent any override."""
        return _ORIGIN_LEVELS[self]


_ORIGIN_LEVELS: dict[Origin, TrustLevel] = {
    Origin.USER_QUERY: TrustLevel.TRUSTED,
    Origin.CONTROL_PLANE: TrustLevel.TRUSTED,
    Origin.VETTED_SYSTEM: TrustLevel.INTERNAL,
    Origin.TOOL_OUTPUT: TrustLevel.UNVERIFIED,
    Origin.WEB_CONTENT: TrustLevel.UNTRUSTED,
    Origin.INBOUND_MESSAGE: TrustLevel.UNTRUSTED,
    Origin.DOCUMENT: TrustLevel.UNTRUSTED,
    Origin.UNKNOWN: TrustLevel.UNVERIFIED,
}
