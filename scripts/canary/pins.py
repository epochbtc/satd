#!/usr/bin/env python3
"""The canary pin manifest: consistency, freshness, and the release gate.

    pins.py check    Every reference to a pinned image in the canary scripts,
                     workflows and Rust harnesses matches scripts/canary/PINS.
                     Offline; runs in CI Lint.
    pins.py report   Compare each pin with upstream's newest stable release
                     and print a Markdown table. `--json` for machines.
    pins.py gate     Exit 1 if any pin breaks the release rule: more than one
                     major version behind upstream, or behind a release that
                     is more than six months old, without a HOLD_<NAME> entry
                     naming the issue that explains why.

report and gate read GitHub through `gh api graphql` (so `gh` must be
authenticated, or GH_TOKEN set) and crates.io over HTTPS.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PINS = ROOT / "scripts/canary/PINS"
BDK_LOCK = ROOT / "scripts/canary/bdk-canary/Cargo.lock"

# Where each pin's releases are published, and which tags are stable ones.
# A pin missing from here and from SIDECARS fails `check`.
GITHUB_SOURCES = {
    "CORE_IMAGE": ("bitcoin/bitcoin", r"^v(\d+)\.(\d+)(?:\.(\d+))?$"),
    "LND_IMAGE": ("lightningnetwork/lnd", r"^v(\d+)\.(\d+)\.(\d+)-beta$"),
    "CLN_IMAGE": ("ElementsProject/lightning", r"^v(\d+)\.(\d+)(?:\.(\d+))?$"),
    "NBXPLORER_IMAGE": ("dgarage/NBXplorer", r"^v(\d+)\.(\d+)\.(\d+)$"),
    "BTCPAY_IMAGE": ("btcpayserver/btcpayserver", r"^v(\d+)\.(\d+)\.(\d+)$"),
    "ELECTRUM_VERSION": ("spesmilo/electrum", r"^(\d+)\.(\d+)\.(\d+)$"),
}
# Crate pins, named the way PINS names its entries so a hold can refer to
# them: HOLD_BDK_WALLET=<issue>.
CRATE_SOURCES = {"BDK_WALLET": ("bdk_wallet", BDK_LOCK)}
# Pinned for reproducibility, not tracked against upstream.
SIDECARS = {"POSTGRES_IMAGE", "ELECTRUM_BASE_IMAGE", "ELECTRUM_APPIMAGE_SHA256"}

# Images CI builds itself rather than pulls.
LOCAL_IMAGES = {"satd"}

# A literal image reference: `name:tag`, `org/name:tag` or
# `registry.host/org/name:tag`, optionally `@sha256:...`. The name must hold a
# letter, so an address such as `127.0.0.1:18903` is not one.
IMAGE_REF = re.compile(
    r"(?<![\w/.:-])((?=[a-z0-9._/-]*[a-z])(?:[a-z0-9][a-z0-9._-]*/)*[a-z0-9][a-z0-9._-]*)"
    r":([A-Za-z0-9][\w.-]*)(?:@sha256:[0-9a-f]{64})?"
)

# Files that run a pinned image, and must take it from PINS.
CONSUMERS = [
    "scripts/canary/*.sh",
    "scripts/fuzz/*.sh",
    ".github/workflows/*.yml",
    "satd/tests/common/core_node.rs",
    "fuzz/fuzz_targets/block_differential.rs",
]

MAX_MAJORS_BEHIND = 1
MAX_AGE = dt.timedelta(days=183)


def load_pins() -> tuple[dict[str, str], dict[str, str]]:
    pins, holds = {}, {}
    for n, line in enumerate(PINS.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            sys.exit(f"{PINS}:{n}: not NAME=value: {line!r}")
        (holds if name.startswith("HOLD_") else pins)[name] = value
    return pins, holds


def image_name(ref: str) -> str:
    """`repo/name:tag@sha256:...` -> `repo/name`."""
    return ref.split("@", 1)[0].rsplit(":", 1)[0]


def check() -> int:
    pins, holds = load_pins()
    errors = []
    for name in pins:
        if name not in GITHUB_SOURCES and name not in SIDECARS:
            errors.append(f"PINS: {name} has no upstream source in pins.py and is not a sidecar")
    for name, value in pins.items():
        if name.endswith("_IMAGE") and not re.search(r":[^@/]+@sha256:[0-9a-f]{64}$", value):
            errors.append(f"PINS: {name} is not pinned by tag and digest: {value}")
    for hold in holds:
        name = hold.removeprefix("HOLD_")
        if name not in pins and name not in CRATE_SOURCES:
            errors.append(f"PINS: {hold} holds a pin that does not exist")
    images = {image_name(v): v for k, v in pins.items() if k.endswith("_IMAGE")}
    pinned_values = set(images.values())
    files = sorted({p for pattern in CONSUMERS for p in ROOT.glob(pattern)})
    for path in files:
        rel = path.relative_to(ROOT)
        for n, line in enumerate(path.read_text().splitlines(), 1):
            seen = set()
            # A pinned image, anywhere, at any other tag or digest.
            for image, pinned in images.items():
                for m in re.finditer(re.escape(image) + r":[\w.\-]+(?:@sha256:[0-9a-f]{64})?", line):
                    seen.add(m.start())
                    if m.group(0) != pinned:
                        errors.append(f"{rel}:{n}: {m.group(0)} does not match PINS ({pinned})")
            # Any other image a docker line names literally: one that was never
            # pinned, or one that left the manifest (a retired image's old
            # reference is not a pinned name any more, so the loop above
            # cannot see it).
            if re.search(r"docker|image", line, re.IGNORECASE):
                for m in IMAGE_REF.finditer(line):
                    if m.start() in seen or m.group(0) in pinned_values or m.group(1) in LOCAL_IMAGES:
                        continue
                    errors.append(f"{rel}:{n}: {m.group(0)} is an image reference not taken from PINS")
    for e in errors:
        print(e, file=sys.stderr)
    if not errors:
        print(f"canary pins consistent: {len(pins)} pins, {len(files)} consumer files")
    return 1 if errors else 0


@dataclass
class Release:
    version: tuple[int, ...]
    name: str
    date: dt.datetime


def parse_version(text: str) -> tuple[int, ...]:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not m:
        raise ValueError(f"no version in {text!r}")
    return tuple(int(g) for g in m.groups() if g is not None)


def major(version: tuple[int, ...]) -> int:
    """The component a breaking release bumps: the first, or for 0.x the second."""
    return version[1] if version[0] == 0 and len(version) > 1 else version[0]


def github_releases(repo: str, pattern: str) -> list[Release]:
    owner, name = repo.split("/")
    query = """
    query($owner: String!, $name: String!) {
      repository(owner: $owner, name: $name) {
        refs(refPrefix: "refs/tags/", first: 100, orderBy: {field: TAG_COMMIT_DATE, direction: DESC}) {
          nodes {
            name
            target {
              __typename
              ... on Commit { committedDate }
              ... on Tag { tagger { date } target { ... on Commit { committedDate } } }
            }
          }
        }
      }
    }"""
    out = subprocess.run(
        ["gh", "api", "graphql", "-f", f"query={query}", "-F", f"owner={owner}", "-F", f"name={name}"],
        check=True, capture_output=True, text=True,
    ).stdout
    releases = []
    for node in json.loads(out)["data"]["repository"]["refs"]["nodes"]:
        m = re.match(pattern, node["name"])
        if not m:
            continue
        target = node["target"]
        when = (target.get("tagger") or {}).get("date") or target.get("committedDate") \
            or (target.get("target") or {}).get("committedDate")
        if not when:
            continue
        version = tuple(int(g) for g in m.groups() if g is not None)
        releases.append(Release(version, node["name"], dt.datetime.fromisoformat(when.replace("Z", "+00:00"))))
    return releases


def crate_releases(crate: str) -> list[Release]:
    req = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{crate}/versions",
        headers={"User-Agent": "satd-canary-pins (https://github.com/epochbtc/satd)"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        versions = json.load(resp)["versions"]
    releases = []
    for v in versions:
        if v["yanked"] or not re.fullmatch(r"\d+\.\d+\.\d+", v["num"]):
            continue
        releases.append(Release(parse_version(v["num"]), v["num"],
                                dt.datetime.fromisoformat(v["created_at"].replace("Z", "+00:00"))))
    return releases


def locked_version(lock: Path, crate: str) -> str:
    m = re.search(r'\[\[package\]\]\nname = "' + re.escape(crate) + r'"\nversion = "([^"]+)"', lock.read_text())
    if not m:
        sys.exit(f"{lock}: no {crate} package")
    return m.group(1)


def freshness(now: dt.datetime) -> list[dict]:
    pins, holds = load_pins()
    rows = []
    tracked = [(name, pins[name], github_releases(*GITHUB_SOURCES[name])) for name in GITHUB_SOURCES]
    for name, (crate, lock) in CRATE_SOURCES.items():
        tracked.append((name, locked_version(lock, crate), crate_releases(crate)))
    for name, pinned_ref, releases in tracked:
        pinned_text = pinned_ref.split("@", 1)[0].rsplit(":", 1)[-1]
        pinned = parse_version(pinned_text)
        newer = sorted((r for r in releases if r.version > pinned), key=lambda r: r.version)
        latest = newer[-1] if newer else None
        majors_behind = major(latest.version) - major(pinned) if latest else 0
        oldest_newer = min(newer, key=lambda r: r.date) if newer else None
        age = now - oldest_newer.date if oldest_newer else dt.timedelta(0)
        violations = []
        if majors_behind > MAX_MAJORS_BEHIND:
            violations.append(f"{majors_behind} majors behind")
        if age > MAX_AGE:
            violations.append(f"behind {oldest_newer.name}, released {age.days} days ago")
        hold = holds.get(f"HOLD_{name}")
        rows.append({
            "pin": name,
            "pinned": pinned_text,
            "latest": latest.name if latest else pinned_text,
            "latest_date": latest.date.date().isoformat() if latest else None,
            "behind": bool(newer),
            "violations": violations,
            "hold": hold,
        })
    return rows


def render(rows: list[dict]) -> str:
    lines = ["| Pin | Pinned | Latest stable | Status |", "|---|---|---|---|"]
    for r in rows:
        if not r["behind"]:
            status = "current"
        elif r["violations"] and r["hold"]:
            status = f"held (#{r['hold']}): " + "; ".join(r["violations"])
        elif r["violations"]:
            status = "**release gate: " + "; ".join(r["violations"]) + "**"
        else:
            status = "behind"
        latest = r["latest"] + (f" ({r['latest_date']})" if r["behind"] and r["latest_date"] else "")
        lines.append(f"| `{r['pin']}` | {r['pinned']} | {latest} | {status} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    report = sub.add_parser("report")
    report.add_argument("--json", action="store_true")
    sub.add_parser("gate")
    args = parser.parse_args()

    if args.cmd == "check":
        return check()
    rows = freshness(dt.datetime.now(dt.timezone.utc))
    if args.cmd == "report":
        print(json.dumps(rows, indent=2) if args.json else render(rows))
        return 0
    print(render(rows))
    failing = [r["pin"] for r in rows if r["violations"] and not r["hold"]]
    if failing:
        print(f"\nrelease gate: {', '.join(failing)} must be bumped, or held with HOLD_<NAME>=<issue>", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
