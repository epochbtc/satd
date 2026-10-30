#!/usr/bin/env python3
"""Turn `cargo llvm-cov report --json --summary-only` into a markdown table.

    cargo llvm-cov report --json --summary-only --output-path cov.json
    python3 scripts/ci/coverage-summary.py cov.json [--repo-root .] >> "$GITHUB_STEP_SUMMARY"

One row per workspace crate (the first path component under the repo root),
then one row per top-level module of `node`, which holds most of the code and
would otherwise be a single number. Files outside the repo root (dependencies,
the standard library) are dropped; llvm-cov already leaves out most of them.

The numbers count every line llvm-cov instruments in a file, and that includes
`#[cfg(test)]` modules in `src/`, which are nearly always fully covered. Read
the table as a map of where the tests reach, not as a score.
"""

import argparse
import json
import os
import sys
from collections import defaultdict

METRICS = ("lines", "functions", "regions")


def pct(covered, count):
    return f"{100.0 * covered / count:.1f}%" if count else "n/a"


def add(acc, summary):
    for m in METRICS:
        acc[m][0] += summary[m]["covered"]
        acc[m][1] += summary[m]["count"]


def new_acc():
    return {m: [0, 0] for m in METRICS}


def row(name, acc):
    lines_cov, lines_cnt = acc["lines"]
    cells = [pct(*acc[m]) for m in METRICS]
    return f"| {name} | {cells[0]} | {lines_cov}/{lines_cnt} | {cells[1]} | {cells[2]} |"


def table(title, groups):
    out = [f"#### {title}", "",
           "| | Lines | Lines covered | Functions | Regions |",
           "|---|---:|---:|---:|---:|"]
    # Largest first: that is where a percentage point means the most code.
    for name in sorted(groups, key=lambda k: -groups[k]["lines"][1]):
        out.append(row(f"`{name}`", groups[name]))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("json_path")
    ap.add_argument("--repo-root", default=".")
    args = ap.parse_args()

    root = os.path.realpath(args.repo_root) + os.sep
    with open(args.json_path) as f:
        report = json.load(f)

    crates = defaultdict(new_acc)
    node_modules = defaultdict(new_acc)
    total = new_acc()
    files = 0
    for data in report["data"]:
        for entry in data["files"]:
            path = os.path.realpath(entry["filename"])
            if not path.startswith(root):
                continue
            rel = path[len(root):].split(os.sep)
            if rel[0].startswith("<"):
                # Dependency sources llvm-cov remaps to `<WORKSPACE>/...`
                # (tokio's macros, for one); not this repository's code.
                continue
            files += 1
            add(crates[rel[0]], entry["summary"])
            add(total, entry["summary"])
            if rel[:2] == ["node", "src"] and len(rel) > 2:
                module = rel[2][:-3] if rel[2].endswith(".rs") else rel[2]
                add(node_modules[module], entry["summary"])

    if files == 0:
        # An empty report would print a table of nothing and read as a pass.
        print(f"error: no files under {root} in {args.json_path}", file=sys.stderr)
        return 1

    out = ["### Test coverage", "",
           f"Total: **{pct(*total['lines'])}** of {total['lines'][1]} lines, "
           f"{pct(*total['functions'])} of functions, {pct(*total['regions'])} of regions, "
           f"across {files} files.", ""]
    out += table("By crate", crates) + [""]
    out += table("`node` by module", node_modules) + [""]
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
