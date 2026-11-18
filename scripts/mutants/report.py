#!/usr/bin/env python3
"""Summarise a cargo-mutants run: a markdown report, plus GitHub annotations.

    python3 scripts/mutants/report.py mutants.out/outcomes.json [more.json...] \
        [--listed N] [--note TEXT] [--summary "$GITHUB_STEP_SUMMARY"] [--annotate]

A *missed* mutant is a change to the code that every test of its crate still
passed: either the behaviour is untested, or the mutant is equivalent to the
original (it cannot change any observable result). Each one needs a person to
say which. A *timeout* usually means the mutant made a loop spin forever,
which a test did notice, by hanging.

cargo-mutants runs only the mutated crate's own tests. A mutant in `node`
that only the `satd` regtest suite would catch is reported here as missed.

Missed mutants a person has already judged (equivalent, or caught by a test
outside the crate) are listed in known-missed.tsv, beside this script. They
are counted and listed apart from the new ones, which are the findings; see
that file for how a row names its mutant. --known gives another file, and
--source-root the checkout the mutants' files are read from (default: the
current directory).

Several outcomes files (the parts of one sharded run) are reported as one.
--listed is how many mutants were in scope. When the run was cut short by the
time budget it tested fewer, and the report says so. --annotate also prints a
`::warning` line per missed mutant, which GitHub shows on the changed line of
a pull request. The report is appended to --summary when given, and printed
otherwise; annotations always go to stdout, where the runner reads them.
"""

import argparse
import json
import os
import sys

MAX_ROWS = 200


def mutant(outcome):
    scenario = outcome["scenario"]
    return scenario.get("Mutant") if isinstance(scenario, dict) else None


def read_known(path):
    """The rows of known-missed.tsv, keyed by (file, column, mutation, line).

    A malformed row is named on stderr and skipped: its mutant is then
    reported as new, which is safe, rather than failing the report."""
    rows = {}
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for n, raw in enumerate(f, 1):
            if raw.startswith("#") or not raw.strip():
                continue
            fields = raw.rstrip("\r\n").split("\t")
            try:
                file, column, mutation, kind, why, line = fields
                rows[(file, int(column), mutation, line)] = (kind, why)
            except ValueError:
                print(f"warning: {path}:{n}: not 6 tab-separated fields with a numeric "
                      "column; row ignored", file=sys.stderr)
    return rows


class Sources:
    """Source lines of the mutated files, trimmed, read once each."""

    def __init__(self, root):
        self.root, self.files = root, {}

    def lines(self, file):
        if file not in self.files:
            try:
                with open(os.path.join(self.root, file)) as f:
                    self.files[file] = f.read().split("\n")
            except OSError:
                self.files[file] = None
        return self.files[file]

    def key(self, m):
        """The known-missed key of a mutant, or None when its file is unreadable."""
        lines = self.lines(m["file"])
        start = m["span"]["start"]
        if lines is None or start["line"] > len(lines):
            return None
        raw = lines[start["line"] - 1]
        line = raw.strip()
        # A line that appears twice in its function (in its file, for a
        # mutant outside any function) would make one row stand for both
        # copies, hiding a new one: such a mutant never matches.
        fn = (m.get("function") or {}).get("span")
        scope = lines[fn["start"]["line"] - 1 : fn["end"]["line"]] if fn else lines
        if sum(1 for r in scope if r.strip() == line) > 1:
            return None
        column = start["column"] - (len(raw) - len(raw.lstrip()))
        return (m["file"], column, m["name"].split(": ", 1)[-1], line)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("outcomes", nargs="+")
    ap.add_argument("--listed", type=int)
    ap.add_argument("--note", default="")
    ap.add_argument("--summary")
    ap.add_argument("--annotate", action="store_true")
    ap.add_argument("--known", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                    "known-missed.tsv"))
    ap.add_argument("--source-root", default=".")
    args = ap.parse_args()
    known = read_known(args.known)
    sources = Sources(args.source_root)

    tested = []
    for path in args.outcomes:
        with open(path) as f:
            tested += [o for o in json.load(f)["outcomes"] if mutant(o)]
    by = {}
    for o in tested:
        by.setdefault(o["summary"], []).append(o)
    missed, judged = [], []
    for o in by.get("MissedMutant", []):
        k = sources.key(mutant(o))
        if k in known:
            judged.append((o, known[k]))
        else:
            missed.append(o)
    timeouts = by.get("Timeout", [])
    caught = len(by.get("CaughtMutant", []))
    unviable = len(by.get("Unviable", []))
    viable = caught + len(missed) + len(judged) + len(timeouts)

    out = ["### Mutation testing", ""]
    if args.note:
        out += [args.note, ""]
    scope = f" of {args.listed} in scope" if args.listed is not None else ""
    out.append(f"Tested **{len(tested)}**{scope}: {caught} caught, "
               f"**{len(missed)} missed**, {len(timeouts)} timed out, "
               f"{unviable} unviable (did not compile).")
    if judged:
        out.append(f"Also missed, as expected: {len(judged)} that known-missed.tsv lists as "
                   "equivalent or as caught by a test outside the crate.")
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
    if judged:
        out += ["#### Missed as expected (known-missed.tsv)", "", "| Location | Mutation | Kind | Why |",
                "|---|---|---|---|"]
        for o, (kind, why) in sorted(judged, key=lambda j: mutant(j[0])["name"]):
            m = mutant(o)
            what = m["name"].split(": ", 1)[-1].replace("|", chr(92) + "|")
            out.append(f"| `{m['file']}:{m['span']['start']['line']}` | {what} | {kind} | {why} |")
        out.append("")
    # A row whose line changed or went no longer names its mutant: a person
    # should judge that mutant again, and fix or drop the row.
    stale = []
    for (file, _, mutation, line) in sorted(known):
        lines = sources.lines(file)
        if lines is not None and not any(raw.strip() == line for raw in lines):
            stale.append(f"- `{file}`: {mutation}")
    if stale:
        out += ["#### known-missed.tsv rows whose line is gone", "",
                "Each mutant is reported as new again when it is missed; judge it afresh "
                "and fix or drop its row.", ""] + stale + [""]
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
