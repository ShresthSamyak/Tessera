"""Integrations that plug Tessera into existing agent frameworks.

Each integration adapts a host framework's tool-calling pipeline onto a Tessera
:class:`~tessera.session.Session`, so the same provenance/flow-rule/capability
enforcement applies without rewriting the agent. Integrations keep their host
dependency *optional* — importing :mod:`tessera.integrations.agentdojo` does not
require ``agentdojo`` to be installed; it only binds to it if present.
"""
