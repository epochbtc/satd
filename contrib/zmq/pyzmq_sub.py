#!/usr/bin/env python3
"""Check the sequence published by satd's events/examples/zmtp_pub.rs with a
libzmq SUB socket (pyzmq).

usage: pyzmq_sub.py ENDPOINT [PREFIX...]

With no PREFIX it subscribes to everything. It reads the messages whose
topic matches a prefix, in order, compares each with the expected one, and
exits 0 when all of them arrived intact.
"""

import sys

import zmq

TOPICS = [b"hashblock", b"hashtx", b"rawblock", b"rawtx", b"sequence"]
LENS = [0, 1, 32, 255, 256, 1000, 65535, 65536, 300000]
COUNT = 46
LAST_LEN = 4 << 20


def expected(i):
    if i + 1 == COUNT:
        topic, n = b"rawblock", LAST_LEN
    else:
        topic, n = TOPICS[i % len(TOPICS)], LENS[i % len(LENS)]
    # Byte j is (i * 7 + j) % 251, which repeats every 251 bytes.
    period = bytes((i * 7 + j) % 251 for j in range(251))
    body = (period * (n // 251 + 1))[:n]
    return topic, body, i.to_bytes(4, "little")


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    endpoint = sys.argv[1]
    prefixes = [p.encode() for p in sys.argv[2:]] or [b""]

    ctx = zmq.Context.instance()
    sock = ctx.socket(zmq.SUB)
    sock.setsockopt(zmq.RCVTIMEO, 30000)
    sock.setsockopt(zmq.LINGER, 0)
    for p in prefixes:
        sock.setsockopt(zmq.SUBSCRIBE, p)
    sock.connect(endpoint)

    want = [expected(i) for i in range(COUNT)]
    want = [m for m in want if any(m[0].startswith(p) for p in prefixes)]
    for k, (topic, body, seq) in enumerate(want):
        try:
            parts = sock.recv_multipart()
        except zmq.Again:
            print(f"pyzmq: timed out waiting for message {k} ({topic.decode()})", file=sys.stderr)
            return 1
        if parts != [topic, body, seq]:
            got = [len(p) for p in parts]
            print(
                f"pyzmq: message {k}: got topic {parts[0]!r}, part sizes {got}; "
                f"want topic {topic!r}, body {len(body)} bytes",
                file=sys.stderr,
            )
            return 1
    sock.close()
    total = sum(len(b) for _, b, _ in want)
    print(f"pyzmq {zmq.zmq_version()}: OK, {len(want)} messages, {total} body bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
