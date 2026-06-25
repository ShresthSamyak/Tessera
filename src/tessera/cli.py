"""``tessera`` command-line entry point.

Wraps an upstream MCP server with the Tessera proxy:

    tessera run --strictness balanced -- python -m my_mcp_server

Everything after ``--`` is the command used to launch the upstream server.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from tessera import __version__
from tessera.policy import PolicyResult, Strictness
from tessera.proxy import StdioProxy


def _console_hitl(result: PolicyResult, explanation: str) -> bool:
    """Prompt for approval on stderr (stdout is the MCP channel)."""
    print("\n=== Tessera: human approval required ===", file=sys.stderr)
    print(explanation, file=sys.stderr)
    print("Approve this action? [y/N] ", end="", file=sys.stderr, flush=True)
    try:
        answer = input().strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tessera",
        description="A provenance control plane for tool-using agents (MCP proxy).",
    )
    parser.add_argument("--version", action="version", version=f"tessera {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run the proxy in front of an upstream MCP server.")
    run.add_argument(
        "--strictness",
        choices=[s.value for s in Strictness],
        default=Strictness.BALANCED.value,
        help="Point on the dynamism<->containment frontier (default: balanced).",
    )
    run.add_argument(
        "--ledger",
        metavar="PATH",
        default=None,
        help="Write the append-only audit ledger to this JSONL file.",
    )
    run.add_argument(
        "--allow-host",
        action="append",
        default=[],
        metavar="HOST",
        help="Hostname whose URLs survive output sanitization (repeatable).",
    )
    run.add_argument(
        "--approve",
        choices=["console", "deny"],
        default="deny",
        help="How to resolve escalations (default: deny, i.e. fail closed).",
    )
    run.add_argument(
        "upstream",
        nargs=argparse.REMAINDER,
        help="-- followed by the command that launches the upstream server.",
    )

    bench = sub.add_parser(
        "bench",
        help="Evaluate the containment / utility-tax frontier on the built-in suite.",
    )
    bench.add_argument(
        "--detail",
        action="store_true",
        help="Show the per-scenario outcome for each strictness setting.",
    )
    return parser


def _clean_upstream(argv: list[str]) -> list[str]:
    return [a for a in argv if a != "--"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        upstream = _clean_upstream(args.upstream)
        if not upstream:
            parser.error("provide the upstream server command after '--'")
        proxy = StdioProxy(
            upstream_cmd=upstream,
            strictness=Strictness(args.strictness),
            ledger_path=args.ledger,
            allowlist=frozenset(h.lower() for h in args.allow_host),
            hitl=_console_hitl if args.approve == "console" else None,
        )
        proxy.run()
        return 0

    if args.command == "bench":
        from tessera.eval.harness import evaluate_frontier, format_frontier

        points = evaluate_frontier()
        print("Tessera frontier -- attack containment vs. utility tax\n")
        print(format_frontier(points, detail=args.detail))
        print(
            "\nHigher containment with lower tax is better. The strictness modes"
            " trade off\nalong the frontier ('balanced' leaks the laundering"
            " attack for lower tax;\n'paranoid' contains everything but"
            " over-taints). 'plan' mode uses the CaMeL-\nstyle interpreter: it"
            " contains injection-introduced steps structurally and uses\nprecise"
            " provenance, so it Pareto-dominates -- full containment at the lower"
            " tax."
        )
        return 0

    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
