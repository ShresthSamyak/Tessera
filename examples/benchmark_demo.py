"""Plot Tessera's containment / utility-tax frontier on the built-in suite.

Run it:

    python examples/benchmark_demo.py     # or: tessera bench --detail

This is the artifact the charter calls the whole pitch: not a single number, but
the curve. Any system blocks every attack by blocking everything; the question
is how much legitimate work survives. The table below shows, per strictness
setting, the fraction of injection attacks contained against the fraction of
benign workflows wrongly blocked.

The headline finding is honest: 'balanced' value-flow matching catches literal
exfiltration cheaply but is evaded by the data-laundering attack; 'paranoid'
context-taint contains laundering too, at the cost of over-tainting benign work.
Choosing between them *is* the security/usability trade -- and a v0.3
declassifier is what would let 'balanced' relieve its residual tax without
giving up containment.
"""

from __future__ import annotations

from tessera.eval.harness import evaluate_frontier, format_frontier


def main() -> None:
    points = evaluate_frontier()
    print("Tessera frontier -- attack containment vs. utility tax")
    print("(built-in suite: 5 injection attacks, 3 benign workflows)\n")
    print(format_frontier(points, detail=True))

    best = max(points, key=lambda p: p.containment_rate - p.utility_tax)
    print(
        f"\nBest containment-minus-tax on this suite: '{best.strictness.value}' "
        f"({best.containment_rate * 100:.0f}% contained, "
        f"{best.utility_tax * 100:.0f}% tax)."
    )


if __name__ == "__main__":
    main()
