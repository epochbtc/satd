#!/usr/bin/env python3
"""Summarise a cargo-mutants run: a markdown report, plus GitHub annotations.

    python3 scripts/mutants/report.py mutants.out/outcomes.json \
        [--listed N] [--note TEXT] [--summary "$GITHUB_STEP_SUMMARY"] [--annotate]

A *missed* mutant is a change to the code that every test of its crate still
passed: either the behaviour is untested, or the mutant is equivalent to the
original (it cannot change any observable result). Each one needs a person to
say which. A *timeout* usually means the mutant made a loop spin forever,
which a test did notice, by hanging.

cargo-mutants runs only the mutated crate's own tests. A mutant in `node`
that only the `satd` regtest suite would catch is reported here as missed.

--listed is how many mutants were in scope. When the run was cut short by the
time budget it tested fewer, and the report says so. --annotate also prints a
`::warning` line per missed mutant, which GitHub shows on the changed line of
a pull request. The report is appended to --summary when given, and printed
otherwise; annotations always go to stdout, where the runner reads them.
"""

import argparse
import json
import sys

MAX_ROWS = 200


def mutant(outcome):
    scenario = outcome["scenario"]
    return scenario.get("Mutant") if isinstance(scenario, dict) else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("outcomes")
    ap.add_argument("--listed", type=int)
    ap.add_argument("--note", default="")
    ap.add_argument("--summary")
    ap.add_argument("--annotate", action="store_true")
    args = ap.parse_args()

    with open(args.outcomes) as f:
        data = json.load(f)

    tested = [o for o in data["outcomes"] if mutant(o)]
    by = {}
    for o in tested:
        by.setdefault(o["summary"], []).append(o)
    missed = by.get("MissedMutant", [])
    timeouts = by.get("Timeout", [])
    caught = len(by.get("CaughtMutant", []))
    unviable = len(by.get("Unviable", []))
    viable = caught + len(missed) + len(timeouts)

    out = ["### Mutation testing", ""]
    if args.note:
        out += [args.note, ""]
    scope = f" of {args.listed} in scope" if args.listed is not None else ""
    out.append(f"Tested **{len(tested)}**{scope}: {caught} caught, "
               f"**{len(missed)} missed**, {len(timeouts)} timed out, "
               f"{unviable} unviable (did not compile).")
    if viable:
        out.append(f"Caught or timed out: {100.0 * (caught + len(timeouts)) / viable:.1f}% "
                   "of the mutants that compiled.")
    if args.listed is not None and len(tested) < args.listed:
        out.append(f"The time budget ran out after {len(tested)} of {args.listed}; "
                   "the rest were not tested.")
    out.append("")

    def table(title, rows):
        if not rows:
            return []
        lines = [f"#### {title}", "", "| Location | Function | Mutation |", "|---|---|---|"]
        for o in sorted(rows, key=lambda o: mutant(o)["name"])[:MAX_ROWS]:
            m = mutant(o)
            loc = f"{m['file']}:{m['span']['start']['line']}"
            fn = (m.get("function") or {}).get("function_name", "")
            # The name ends with the mutation, after the location prefix.
            what = m["name"].split(": ", 1)[-1]
            if fn and what.endswith(f" in {fn}"):
                what = what[: -len(f" in {fn}")]
            lines.append(f"| `{loc}` | `{fn}` | {what.replace('|', chr(92) + '|')} |")
        if len(rows) > MAX_ROWS:
            lines.append(f"| ... | | {len(rows) - MAX_ROWS} more in the artifact |")
        return lines + [""]

    out += table("Missed: no test of the crate failed", missed)
    out += table("Timed out", timeouts)
    report = "\n".join(out) + "\n"
    if args.summary:
        with open(args.summary, "a") as f:
            f.write(report)
    else:
        sys.stdout.write(report)

    if args.annotate:
        for o in missed:
            m = mutant(o)
            what = m["name"].split(": ", 1)[-1]
            print(f"::warning file={m['file']},line={m['span']['start']['line']},"
                  f"title=Missed mutant::No test in {m['package']} fails if we {what}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
