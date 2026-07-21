# Manual Style Guide

House style for the Operator Manual (`docs/manual/src/`). This is a contributor
document; it is not published. Review every manual PR against it.

The rules borrow selectively from ASD-STE100 Simplified Technical English. Full
STE conformance is not a goal.

## Sentences and paragraphs

- Keep sentences under about 25 words. In procedures, under 20. One idea per
  sentence.
- No em-dashes, anywhere. Restructure the sentence instead: split it, or use a
  colon, a comma, or parentheses. Use parentheses sparingly.
- No nested asides. If a qualification matters, give it its own sentence. If it
  does not matter, cut it.
- Keep description and instruction in separate paragraphs. Description says what
  the node does. Instruction tells the operator what to do, in the imperative:
  "Use `--fast-start-sha256=<hex>` to set the required digest."
- Plain technical register, like a man page. State facts. Do not sell, and do
  not editorialize about the quality of the design.

## Words

Banned in the manual (each is filler, marketing, or both): seamless, robust,
comprehensive, battle-tested, first-class, powerful, elegant, simply, just,
essentially, crucially, importantly, honest, note that, it's worth noting,
in other words, the net effect.

Avoid rhetorical patterns: "not X but Y" framing, lists of exactly three for
rhythm, a bold lead-in phrase at the start of a paragraph, and parentheticals
that justify a choice rather than add a fact.

Bold is for defined terms at first use and for table/callout structure. Do not
bold for emphasis mid-sentence.

Metaphor and analogy are allowed once, when a concept is first introduced, if
they carry real explanatory weight. Never inside procedures or reference
tables.

## Controlled glossary

One term per concept. Do not use synonyms for variety.

| Term | Use for | Do not use |
|---|---|---|
| verify | script, signature, and proof checks ("script verification", "shadow verification") | validate, check |
| validate | consensus acceptance of blocks, transactions, and the chain ("block validation", "fully validated") | verify, check |
| check | generic tests that are neither of the above; verb only | as a noun ("a check") where verify/validate fits |
| option | a configuration setting in general | knob, switch, toggle, setting |
| flag | an option in command-line form (`-assumevalid`) | argument, switch |
| config key | an option in `bitcoin.conf` form | conf option, setting |
| satd | the program | the daemon, the binary (except when the file itself is meant) |
| the node | a running satd instance | the daemon, the server |
| endpoint | an HTTP path (Esplora, streaming) | route, API (for a single path) |
| method | a JSON-RPC procedure | call, endpoint, command |
| tool | an MCP tool | method, endpoint |
| lint | offline checks of a policy or config file | validate, verify |

Extend this table when a new concept needs a name. Pick one term and add a row.

## Callouts

Use blockquote callouts with a bold label, one of:

> **Note.** Supplementary fact the reader can skip.

> **Warning.** Risk of data loss, funds loss, or downtime.

> **Difference from Bitcoin Core.** Behavior that deviates from Core, stated
> precisely.

Do not invent other labels, and do not express warnings as ordinary prose.

## Headings and links

Changing a heading changes its anchor. Before renaming a heading, grep the
repository for links to the old anchor and update them in the same commit.
