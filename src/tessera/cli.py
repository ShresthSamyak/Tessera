"""``tessera`` command-line entry point.

Wraps an upstream MCP server with the Tessera proxy:

    tessera run --strictness balanced -- python -m my_mcp_server

Everything after ``--`` is the command used to launch the upstream server.
"""

from __future__ import annotations

import argparse
import os
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
        "--ledger-key-env",
        metavar="VAR",
        default=None,
        help="Env var holding the key to HMAC-chain the ledger with. Only adds "
        "tamper-resistance if the verifier's key is not readable from here.",
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

    verify = sub.add_parser(
        "verify",
        help="Check an audit ledger's hash chain for tampering.",
    )
    verify.add_argument("path", help="Path to the ledger JSONL file.")
    verify.add_argument(
        "--key-env",
        metavar="VAR",
        default=None,
        help="Env var holding the HMAC key the ledger was written with.",
    )
    verify.add_argument(
        "--expected-head",
        metavar="HASH",
        default=None,
        help="Externally-anchored hash of the last entry. Without it, a "
        "truncated tail cannot be detected.",
    )
    return parser


def _clean_upstream(argv: list[str]) -> list[str]:
    return [a for a in argv if a != "--"]


def _key_from_env(
    var: Optional[str], parser: argparse.ArgumentParser
) -> Optional[bytes]:
    """Read an HMAC key from an environment variable (never from a flag).

    Taken as the raw UTF-8 bytes of the value, so ``openssl rand -hex 32``
    output works directly. A key on the command line would land in shell
    history and the process table, so it is deliberately not accepted there.
    """
    if var is None:
        return None
    value = os.environ.get(var)
    if not value:
        parser.error(f"environment variable {var!r} is unset or empty")
    return value.encode("utf-8")


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
            ledger_key=_key_from_env(args.ledger_key_env, parser),
        )
        proxy.run()
        return 0

    if args.command == "verify":
        from tessera.ledger import verify_ledger

        result = verify_ledger(
            args.path,
            hmac_key=_key_from_env(args.key_env, parser),
            expected_head=args.expected_head,
        )
        print(result.describe())
        if result.ok:
            print(f"head: {result.head}")
            if args.expected_head is None:
                print(
                    "note: a hash chain cannot detect a truncated tail. Record "
                    "the head above and pass it as --expected-head to close that gap."
                )
            return 0
        return 1

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
