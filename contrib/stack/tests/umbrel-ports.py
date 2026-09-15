#!/usr/bin/env python3
"""Check the Umbrel package's host ports against the store's rules.

Umbrel's app store has one host port space: an app's manifest `port` and
every port any app publishes share it, and the store linter refuses a
collision. The linter only runs in the store repository, though, so this
keeps the invariants it cannot see, and the ones it would, next to the
package:

- every published port is mapped 1:1, host port equal to container port;
- satd listens on that same number, via the server's listener flags, so a
  peer that learns the P2P address dials satd and not another node;
- the numbers live in exports.sh, and none is a port the Bitcoin apps satd
  users run beside it already own.
"""
import os
import re
import sys

# Host ports held by apps in the Umbrel store that satd users commonly run
# alongside it. The store linter checks the full set; these are the ones this
# package once collided with, or would by default.
TAKEN = {
    "3001": "Ride The Lightning (manifest port)",
    "8332": "Bitcoin Node (RPC)",
    "8333": "Bitcoin Node (P2P)",
    "9332": "Bitcoin Knots (RPC)",
    "9333": "Bitcoin Knots (P2P)",
    "50001": "Electrs",
    "50002": "Fulcrum",
}

# The server flag that sets each published listener, and how to find the port
# in its value.
FLAGS = {
    "--port": r"^\$\{(\w+)\}$",
    "--rpctlsbind": r"^0\.0\.0\.0:\$\{(\w+)\}$",
    "--electrumtlsbind": r"^0\.0\.0\.0:\$\{(\w+)\}$",
    "--esploratlsbind": r"^0\.0\.0\.0:\$\{(\w+)\}$",
    "--mcpport": r"^\$\{(\w+)\}$",
}


def main(pkg):
    compose = open(os.path.join(pkg, "docker-compose.yml")).read()
    exports = dict(
        re.findall(
            r'^export ([A-Z][A-Z0-9_]*)="([0-9]+)"\s*$',
            open(os.path.join(pkg, "exports.sh")).read(),
            re.M,
        )
    )
    manifest = open(os.path.join(pkg, "umbrel-app.yml")).read()
    failed = False

    def ok(msg):
        print(f"  ok    {msg}")

    def bad(msg):
        nonlocal failed
        print(f"  FAIL  {msg}")
        failed = True

    # The server service's block: from `  server:` to the next top-level
    # service key.
    m = re.search(r"^  server:\n(.*?)(?=^  \S|\Z)", compose, re.M | re.S)
    if not m:
        raise SystemExit("umbrel-ports.py: no server service in docker-compose.yml")
    server = m.group(1)

    published = []
    pm = re.search(r"^    ports:\n((?:      .*\n|\s*#.*\n)+)", server, re.M)
    if not pm:
        raise SystemExit("umbrel-ports.py: the server service publishes nothing")
    for line in pm.group(1).splitlines():
        spec = re.match(r'^\s+- "?([^"#]+?)"?\s*$', line)
        if not spec:
            continue
        spec = spec.group(1)
        pair = re.match(r"^\$\{(\w+)\}:\$\{(\w+)\}$", spec)
        if not pair:
            bad(f"{spec}: not `${{VAR}}:${{VAR}}`; the number belongs in exports.sh")
            continue
        host, container = pair.groups()
        if host != container:
            bad(f"{spec}: host and container ports differ")
            continue
        if host not in exports:
            bad(f"{spec}: {host} is not exported with a number in exports.sh")
            continue
        ok(f"{host}={exports[host]} is published 1:1")
        published.append(host)

    listened = []
    for flag, pattern in FLAGS.items():
        fm = re.search(rf"^\s+- {re.escape(flag)}=(\S+)\s*$", server, re.M)
        if not fm:
            bad(f"the server sets no {flag}, so satd listens on its default")
            continue
        vm = re.match(pattern, fm.group(1))
        if not vm:
            bad(f"{flag}={fm.group(1)} does not name one exported port")
            continue
        var = vm.group(1)
        listened.append(var)
        if var in published:
            ok(f"{flag} listens on the published {var}")
        else:
            bad(f"{flag} listens on {var}, which is not published")
    for var in published:
        if var not in listened:
            bad(f"{var} is published but no listener flag moves satd onto it")

    port = re.search(r"^port: (\d+)\s*$", manifest, re.M)
    if not port:
        raise SystemExit("umbrel-ports.py: umbrel-app.yml has no port")
    owners = {exports[v]: v for v in published}
    if port.group(1) in owners:
        bad(f"manifest port {port.group(1)} is also published as {owners[port.group(1)]}")
    for owner, num in [(v, exports[v]) for v in published] + [("manifest port", port.group(1))]:
        if num in TAKEN:
            bad(f"{owner} {num} collides with {TAKEN[num]}")
        else:
            ok(f"{owner} {num} is clear of the Bitcoin apps' ports")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
