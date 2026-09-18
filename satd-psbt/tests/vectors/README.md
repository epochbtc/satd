# Vendored BIP test vectors

Copied verbatim from the BIPs repository so the test suite has an independent
referee rather than satd's own idea of what these fields mean.

| File | Source | Notes |
|---|---|---|
| `bip375_test_vectors.json` | `bip-0375/bip375_test_vectors.json` | 22 invalid and 20 valid PSBTs, plus the `checks` override each vector wants. Version 1.1. |
| `bip370_test_vectors.json` | `bip-0370.mediawiki`, "Test Vectors" | Transcribed from the wiki source, which ships them inline rather than as a file. 24 invalid, 14 valid, 10 lock-time determination cases. |
| `bip374_verify_proof.csv` | `bip-0374/test_vectors_verify_proof.csv` | 15 rows, 8 of them expected to fail. |
| `bip374_generate_proof.csv` | `bip-0374/test_vectors_generate_proof.csv` | 11 rows, 3 of them expected to fail. |

Source repository: <https://github.com/bitcoin/bips>, commit `55083d36`,
fetched 2026-09-17. BIP text and vectors are BSD-2-Clause.

`bip370_test_vectors.json` is the one file with a satd-side transformation:
each `* Case:` heading became a `description`, each `Base64 String` a `psbt`,
and the lock-time group's "should be computed to be N" headings became a
`locktime` field (`null` where the BIP says the lock time cannot be computed).
Nothing else was changed, and no vector was dropped.

The `supplementary` object inside a BIP 375 vector is diagnostic material the
BIP explicitly says not to validate against. satd's tests read only
`description`, `psbt` and `checks`.
