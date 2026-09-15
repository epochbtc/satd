#!/usr/bin/env python3
"""Check which host ports the compose overlays publish.

Ports published by docker are reachable from off the host and bypass the
appliance's inbound nftables chain, so each one is a deliberate decision.
Anything not bound to loopback has to appear in ALLOWED with a reason.
"""
import glob
import os
import re
import sys

# port -> why it is allowed to face the network
ALLOWED = {
    "9735": "Lightning P2P (LND) -- useless unless publicly reachable",
    "9736": "Lightning P2P (CLN) -- useless unless publicly reachable",
    "8080": "LND REST -- TLS with LND's own certificate, macaroon-gated",
    "443": "proxy: RTL over TLS",
    "8443": "proxy: Cashu mint over TLS",
    "49393": "proxy: BTCPay over TLS",
    "9443": "proxy: satd metrics over TLS",
    # satd's own published ports are all natively TLS or Bitcoin P2P; they
    # live in compose.yml and are checked by the stack smoke test.
    "8336": "satd JSON-RPC, native TLS",
    "50002": "satd Electrum, native TLS",
    "3001": "satd Esplora, native TLS",
    "9336": "satd metrics / health / status page, native TLS",
    "8333": "Bitcoin P2P (mainnet)",
    "18333": "Bitcoin P2P (testnet3)",
    "18444": "Bitcoin P2P (regtest)",
    "38333": "Bitcoin P2P (signet)",
    "48333": "Bitcoin P2P (testnet4)",
    "8339": "satd MCP, native TLS plus a bearer token",
    # The Umbrel package's own block, clear of the ports other store apps use.
    "8433": "Bitcoin P2P (Umbrel package)",
    "8436": "satd JSON-RPC, native TLS (Umbrel package)",
    "50012": "satd Electrum, native TLS (Umbrel package)",
    "8431": "satd Esplora, native TLS (Umbrel package)",
    "8439": "satd MCP, native TLS plus a bearer token (Umbrel package)",
}

# "${VAR:-default}" -> "default"; "${VAR}" -> "" (unknown at rest)
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


EXPORT = re.compile(r'^export ([A-Za-z_][A-Za-z0-9_]*)="([0-9]+)"\s*$', re.M)


def exports_beside(path):
    """Numeric values from an Umbrel `exports.sh` next to the compose file.

    Umbrel puts every app's exports into the compose environment, so a port
    named `${APP_SATD_P2P_PORT}` there is whatever exports.sh says it is.
    """
    ex = os.path.join(os.path.dirname(path), "exports.sh")
    return dict(EXPORT.findall(open(ex).read())) if os.path.exists(ex) else {}


def resolve(text, env=None):
    env = env or {}
    return VAR.sub(lambda m: env.get(m.group(1)) or m.group(2) or "", text)


def published(path):
    """Yield the raw port specs under each `ports:` key.

    Comments and blank lines inside the block are skipped rather than ending
    it -- every `ports:` in this tree opens with an explanatory comment, and
    treating that as the end of the block silently checked nothing.
    """
    out, in_ports, blocks = [], False, 0
    for line in open(path):
        if re.match(r"^    ports:\s*$", line):
            in_ports = True
            blocks += 1
            continue
        if not in_ports:
            continue
        if not line.strip() or line.strip().startswith("#"):
            continue
        m = re.match(r'^      - "?([^"\n]+)"?\s*$', line)
        if m:
            out.append(m.group(1))
        else:
            in_ports = False
    if blocks and not out:
        raise SystemExit(
            f"published-ports.py: {path} has {blocks} ports: block(s) but "
            "none parsed -- the parser is out of step with the file"
        )
    return out


def main(*roots):
    # `compose*.yml`, not `compose.*.yml`: the latter does not match
    # compose.yml itself, so the base stack's own ports went unchecked.
    paths = []
    for root in roots:
        if os.path.isdir(root):
            paths += glob.glob(os.path.join(root, "compose*.yml"))
            paths += glob.glob(os.path.join(root, "docker-compose.yml"))
        elif os.path.exists(root):
            paths.append(root)
        else:
            raise SystemExit(f"published-ports.py: no such path: {root}")
    if not paths:
        raise SystemExit(f"published-ports.py: nothing to check under {roots}")

    failed = False
    for path in sorted(paths):
        name = os.path.basename(path)
        env = exports_beside(path)
        for spec in published(path):
            parts = resolve(spec, env).split(":")
            # ADDR:HOST:CONTAINER, or HOST:CONTAINER
            addr = parts[0] if len(parts) == 3 else None
            host = parts[-2] if len(parts) >= 2 else parts[0]
            if not host:
                # An unset variable resolves to nothing, and "" is in no
                # allow-list: say which, rather than a bare FAIL on ":".
                print(f"  FAIL  {name} publishes {spec}, whose host port resolves to nothing")
                failed = True
                continue
            if addr and addr not in ("0.0.0.0", "::"):
                print(f"  ok    {name} publishes {spec} on {addr}")
            elif host in ALLOWED:
                print(f"  ok    {name} publishes {host} ({ALLOWED[host]})")
            else:
                print(
                    f"  FAIL  {name} publishes {spec} on every interface; "
                    f"bind it to 127.0.0.1 or add {host} to ALLOWED with a reason"
                )
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
