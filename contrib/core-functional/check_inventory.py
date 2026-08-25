#!/usr/bin/env python3
"""Validate inventory.toml against the pinned Core test list.

The inventory is the harness's honesty mechanism. Every Core functional test
file gets exactly one row saying either "we run this" or "we skip it, and here
is why". The checker exists so that stays true without anyone having to
remember: it fails on a file with no row, a row with no file, a skip with no
reason, a reason outside the taxonomy, and a reason that requires a follow-up
note but does not have one.

The scoreboard published in the manual is derived from this file, so a row that
lies is a claim that lies.

Exit status is 0 when the inventory is valid, 1 when it is not.
"""

import argparse
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Why a test is not run. Keep this list short: a taxonomy that grows a bucket
# per awkward test stops describing anything. Every entry states a property of
# satd or of the harness, never "this one fails".
TAXONOMY = {
    "no-wallet": "needs the legacy Core wallet, which satd does not implement",
    "no-tool": "needs a Core-only binary (bitcoin-tx/-util/-wallet/-chainstate/bench)",
    "no-qt": "needs the Qt GUI",
    "no-core-zmq": "needs Core's ZMQ topics; satd's ZMQ carries the satd-events wire",
    "no-ipc": "needs Core's multiprocess/IPC interface",
    "no-usdt": "needs USDT tracepoints",
    "core-internal": "asserts on Core implementation details satd does not share "
                     "(LevelDB files, blk*.dat layout, settings.json, ...)",
    "core-net-policy": "asserts on Core-specific net policy artifacts "
                       "(anchors.dat, asmap, banlist format)",
    "core-log": "greps debug.log for a line satd has no equivalent of, and no "
                "honest debuglog_map.toml rule can supply it",
    "rpc-missing": "needs an RPC or RPC field satd does not implement yet; "
                   "note must name the follow-up",
    "feature-missing": "needs a node feature satd does not implement yet; "
                       "note must say which",
    "prev-release": "needs binaries from previous releases",
    "harness": "blocked by the harness itself, not by satd; note must say what",
    "cache": "needs the framework's cached 199-block chain",
    "flaky-quarantine": "temporarily quarantined; note must reference an issue",
    "needs-triage": "measured as failing, cause not yet attributed; note must "
                    "carry the observed error. Temporary -- this bucket is work, "
                    "and it should only ever shrink",
}

# Reasons where "because X" is not enough and the row must name the follow-up
# work, so the skip cannot quietly become permanent.
REQUIRE_NOTE = {"rpc-missing", "feature-missing", "harness", "flaky-quarantine",
                "needs-triage"}


def load_pin() -> dict:
    pin = {}
    for line in (HERE / "PIN").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            pin[key.strip()] = value.strip()
    return pin


def expected_files(tag: str) -> list[str]:
    listing = HERE / f"{tag}-tests.txt"
    if not listing.is_file():
        sys.exit(f"missing test list {listing.name} for pinned tag {tag}")
    return [l.strip() for l in listing.read_text().splitlines() if l.strip()]


def check(inventory_path: Path, tag: str) -> tuple[list[str], list[dict]]:
    """Return (errors, rows)."""
    errors: list[str] = []
    with inventory_path.open("rb") as fh:
        doc = tomllib.load(fh)
    rows = doc.get("test", [])

    seen: dict[str, int] = {}
    for idx, row in enumerate(rows):
        where = f"row {idx + 1}"
        name = row.get("file")
        if not name:
            errors.append(f"{where}: missing `file`")
            continue
        where = name
        if name in seen:
            errors.append(f"{name}: duplicate row (also row {seen[name] + 1})")
        seen[name] = idx

        status = row.get("status")
        if status not in ("run", "skip"):
            errors.append(f"{where}: status must be \"run\" or \"skip\", got {status!r}")
            continue

        reason = row.get("reason")
        note = row.get("note")
        if status == "run":
            if reason:
                errors.append(f"{where}: a `run` row must not carry a `reason`")
        else:
            if not reason:
                errors.append(f"{where}: a `skip` row needs a `reason`")
            elif reason == "unknown":
                errors.append(f"{where}: `reason = \"unknown\"` is not a reason -- triage it")
            elif reason not in TAXONOMY:
                errors.append(
                    f"{where}: reason {reason!r} is not in the taxonomy "
                    f"({', '.join(sorted(TAXONOMY))})"
                )
            elif reason in REQUIRE_NOTE and not note:
                errors.append(f"{where}: reason {reason!r} requires a `note` naming the follow-up")

    expected = expected_files(tag)
    missing = [f for f in expected if f not in seen]
    orphans = [f for f in seen if f not in expected]
    for f in missing:
        errors.append(f"{f}: in {tag}-tests.txt but has no inventory row")
    for f in orphans:
        errors.append(f"{f}: has an inventory row but is not in {tag}-tests.txt")

    return errors, rows


def check_tree(tag: str, core_dir: Path) -> list[str]:
    """Compare the fetched Core tree against the checked-in file list."""
    if not (core_dir / "test" / "functional").is_dir():
        return [f"Core tree missing at {core_dir}"]
    non_scripts = {"combine_logs.py", "create_cache.py", "test_runner.py"}
    on_disk = {p.name for p in (core_dir / "test" / "functional").glob("*.py")} - non_scripts
    expected = set(expected_files(tag))
    errors = []
    for f in sorted(expected - on_disk):
        errors.append(f"{f}: listed in {tag}-tests.txt but not in the fetched tree")
    for f in sorted(on_disk - expected):
        errors.append(f"{f}: in the fetched tree but not in {tag}-tests.txt")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-run-set", action="store_true",
                        help="print the files marked run, one per line")
    parser.add_argument("--summary", action="store_true",
                        help="print the scoreboard and skip breakdown")
    parser.add_argument("--check-tree", action="store_true",
                        help="also verify the fetched Core tree matches the file list")
    parser.add_argument("--inventory", type=Path, default=HERE / "inventory.toml")
    args = parser.parse_args()

    pin = load_pin()
    tag = pin.get("CORE_TAG")
    if not tag:
        sys.exit("PIN has no CORE_TAG")

    errors, rows = check(args.inventory, tag)
    if args.check_tree:
        errors += check_tree(tag, Path(__file__).resolve().parent / "core")

    if errors:
        print(f"inventory.toml: {len(errors)} problem(s)", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    run_set = [r["file"] for r in rows if r["status"] == "run"]

    if args.print_run_set:
        for f in sorted(run_set):
            print(f)
        return 0

    if args.summary:
        total = len(rows)
        print(f"Core {tag}: {len(run_set)}/{total} functional tests run unmodified")
        counts: dict[str, int] = {}
        for row in rows:
            if row["status"] == "skip":
                counts[row["reason"]] = counts.get(row["reason"], 0) + 1
        print()
        print(f"{'reason':<20} {'count':>5}  what it means")
        for reason, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"{reason:<20} {count:>5}  {TAXONOMY[reason]}")
        return 0

    print(f"inventory.toml OK: {len(rows)} rows, {len(run_set)} run, "
          f"{len(rows) - len(run_set)} skip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
