#!/usr/bin/env python3
"""Verify a test_runner results CSV against the run-set it was given.

Core's test_runner exits 0 for a test its own framework skipped at runtime --
an unmet ``skip_if_no_*`` guard, a component the config declares absent -- and
reports it "Skipped". Every row the inventory marks ``run`` claims to run
unmodified against satd, so a runtime skip is an inventory lie: CI stays green
while the scoreboard counts a test that never executed. A test that vanishes
from the results entirely is the same lie told more quietly.

Both are rejected here. The honest fix for either is to make the test actually
run, or to move its row to ``skip`` in inventory.toml with a real reason.
"""

import argparse
import csv
import sys
from pathlib import Path


def check(results_path: Path, expected: list[str]) -> list[str]:
    """Return a list of complaints; empty means the run-set genuinely ran."""
    problems: list[str] = []
    try:
        rows = list(csv.DictReader(results_path.open(newline="")))
    except OSError as e:
        return [f"cannot read results file {results_path}: {e}"]

    seen = {}
    for row in rows:
        name = (row.get("test") or "").strip()
        if not name or name == "ALL":
            continue
        seen[name] = (row.get("status") or "").strip()

    for name, status in sorted(seen.items()):
        if status == "Skipped":
            problems.append(f"{name}: skipped at runtime, but its inventory row says 'run'")

    # test_runner expands some tests into per-variant runs and reports each
    # under a suffixed name -- "p2p_block_sync.py --v1transport". Those are the
    # run, so a file is present if any of its variants is. A test file name
    # never contains a space, so the first one starts the suffix.
    #
    # Matching exactly would fail every such test the moment it is flipped to
    # `run`, which reads as "the harness did not execute it" when in fact it
    # executed twice.
    base_names = {name.split(" ", 1)[0] for name in seen}

    for name in expected:
        if name not in base_names:
            problems.append(f"{name}: in the run-set but absent from the results")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results", type=Path, help="CSV written by test_runner --resultsfile")
    ap.add_argument("expected", nargs="*", help="test files the run-set asked for")
    args = ap.parse_args()

    problems = check(args.results, args.expected)
    if not problems:
        return 0

    print("ERROR: the run-set did not run as the inventory claims:", file=sys.stderr)
    for p in problems:
        print(f"  {p}", file=sys.stderr)
    print(
        "A 'run' row must actually run. Fix the harness so the test executes,\n"
        "or move the row to 'skip' in inventory.toml with an honest reason.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
