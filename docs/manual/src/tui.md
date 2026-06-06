# sat-tui

`sat-tui` is the operator dashboard for satd: a curses-style terminal UI
that connects over JSON-RPC and shows what the node is doing. It is
deliberately read-only — there is no way to change node state from the
TUI. Bitcoin Core has no equivalent shipped surface.

This document is the reference for what the TUI shows. It is not a
walkthrough; for "what should I look at first" guidance, see
[Observability & Metrics](observability.md).

## Running

`sat-tui` is built as part of the workspace and ships in every release
tarball alongside `satd` and `sat-cli`.

```sh
sat-tui                        # mainnet, default RPC port (8332)
sat-tui --regtest              # regtest, port 18443
sat-tui --testnet              # testnet, port 18332
sat-tui --signet               # signet, port 38332
```

### Authentication

Same precedence as `sat-cli`:

1. `--rpcuser` + `--rpcpassword` if both provided.
2. Cookie file at `--rpccookiefile` if provided.
3. Auto-detected cookie under `--datadir` (default `~/.bitcoin`) for the
   active network.

If the cookie rotates while the TUI is running (for example, satd was
restarted), the RPC client re-reads the cookie file and retries once
before surfacing the failure as a "Connecting to satd…" splash.

### Other CLI flags

| Flag | Default | Meaning |
|---|---|---|
| `--rpcconnect <host>` | `127.0.0.1` | RPC host. |
| `--rpcport <port>` | per-network default | Override the auto-detected port. |
| `--datadir <path>` | `~/.bitcoin` | Used to locate the cookie file. |
| `--rpcuser <user>` | — | Userpass auth (with `--rpcpassword`). |
| `--rpcpassword <pass>` | — | Userpass auth (with `--rpcuser`). |
| `--rpccookiefile <path>` | auto | Override cookie path. |

The TUI exits cleanly on `q` or `Ctrl-C` and restores the terminal mode.

## Connection states

Before any view is shown, `sat-tui` is in one of three connection states:

- **"Connecting to satd…"** (yellow, centered) — RPC is unreachable, or
  has returned only failures so far. Common during cold start, satd
  restart, or when auth is misconfigured.
- **Startup splash** — satd is up but is still starting (header scan,
  reindex, address-index backfill). The splash is sourced from satd's
  `getstartupinfo` RPC; see [Startup splash](#startup-splash) below.
- **Active view** — `getblockchaininfo` succeeded; one of the four main
  views is rendered.

A red `✕ stale` indicator in the title bar means the last successful
poll is more than ~3 seconds old. Treat it as "RPC is degraded right
now"; the TUI will recover automatically when polling resumes.

## Views

There are four main views, plus a startup splash and three modal
overlays.

The active view is auto-selected from chain state (`is_ibd`): IBD view
during initial block download, Steady view once synced. The operator can
force a view with `1` / `2` / `3` / `4`; press the same key again to
return to auto-detect.

### Startup splash

Shown while satd is in startup (header scan, reindex, address-index
backfill). The splash is one panel:

| Field | Meaning |
|---|---|
| **Phase** | Current startup phase (e.g. `reindex_scan`, `reindex_connect`, `headers`, `verify`). |
| **Status** | Free-form human-readable description from satd. |
| **Gauge** | Progress through the current phase, 0–100%. |
| **Elapsed** | Wall-clock time since this phase began. |
| **Rate** | Items/sec — blocks, headers, or whatever the phase is iterating over. |
| **ETA** | Estimated remaining time for **this phase only**, not whole startup. |

ETAs are intentionally per-phase: phase 1 (e.g. reindex header scan) and
phase 2 (block replay) have very different per-item costs, and a unified
estimate misleads until phase 2 dominates.

### IBD view (`1`)

Shown while the node is in initial block download. Five panels stacked
vertically:

#### Title bar
Chain name, satd version, `is_ibd` indicator.

#### Progress block
- **Blocks / target** — connected blocks vs. the highest block any peer
  has advertised.
- **blk/s** — blocks connected per second, EMA-smoothed.
- **hdr/s** — headers received per second.
- **ETA** — server-side estimate from satd's `getibdprogress` RPC. The
  server estimate accounts for ~50× variation in per-block validation
  cost across history (early empty blocks vs. modern weight-bound
  blocks); a naive "blocks remaining ÷ blk/s" calculation will be wildly
  wrong, especially in the first few hundred thousand blocks.
- **Peers** — connected peer count.

#### Block map
A bitmap of download state per block group (one cell ≈ many blocks):

| Glyph | Colour | Meaning |
|---|---|---|
| `█` | green | **Connected** — validated and in the chain. |
| `░` | cyan | **Downloaded** — on disk, waiting for sequential connection. |
| `▓` | yellow | **In flight** — requested from a peer, not yet received. |
| `·` | dim | **Pending** — queued for download, not yet requested. |

A healthy IBD shows a leading wave of `█` followed by `░`, with a
narrow `▓` band at the frontier. Long stretches of `▓` mean a peer is
slow or unresponsive; long stretches of `·` mean we are bandwidth-bound
or under peer-count pressure.

#### Sync rate + stats

Two sparklines (~90 seconds of history):

- **blk/s connected** (yellow) — rate of blocks fully validated.
- **blk/s downloaded** (cyan) — rate of blocks pulled from peers, all
  peers summed.

Plus a stats panel: Headers, Connected, Stored, In-Flight, Remaining.

#### Peers table

| Column | Meaning |
|---|---|
| **Addr** | Peer IP and port. |
| **Agent** | Subversion string (`/Satoshi:25.1.0/`, `/satd:0.1.0/`, …). |
| **Recv** | Blocks received from this peer this session. |
| **Assigned** | Blocks currently assigned to this peer for download. |
| **Rate** | Per-peer blk/s, EMA-smoothed. `—` below 0.1 blk/s. |

`Up` / `Down` highlights a row.

### Steady view (`2`)

Default view once `is_ibd=false`. Six stacked panels.

#### Title bar
Health dot, uptime.

| Symbol | Meaning |
|---|---|
| `● ready` (green) | Polling is fresh, node is at tip. |
| `○ syncing` (yellow) | Polling is fresh, node is still syncing minor lag. |
| `✕ stale` (red) | Last poll is older than ~3s. RPC may be degraded. |

#### Chain + Latest block (split)

**Chain (left half):**
- **Height** — current tip height.
- **Difficulty** — raw difficulty value.
- **Hash Rate** — network hashrate from `getmininginfo` (H/s).
- **Last Block** — seconds since the tip block's timestamp. > 1 hour is
  unusual.

**Latest block (right half):**
- **Hash** — tip hash, truncated.
- **Txs** — transaction count.
- **Size / Weight** — bytes / weight units.
- **Fees** — total miner fees collected (BTC).
- **Avg Rate** — average effective fee rate across all txs (sat/vB).

#### Mempool + Fees (split)

**Mempool (left half):**
- **Txs** — unconfirmed transactions.
- **Size** — total bytes.
- **Min Rate** — current mempool minimum fee. **0.0** is the default
  (min-relay floor, ~1 sat/vB). A non-zero value means the mempool is
  full and is evicting low-fee txs; new txs need at least this much to
  enter.
- **Tx Rate** — recent tx-entry rate from `getchaintxstats` (tx/s).
- **Size distribution** — sparkline of vbyte buckets (0, 100, 250, 500,
  1k, 5k, 10k, 50k+).

**Fees (right half):**
Fee tier estimates from `estimatefees` (mempool.space convention):
- **High** — next-block target (1-block confirmation).
- **Medium** — ~30 minute target (3-block).
- **Low** — ~1 hour target (6-block).
- **None** — economy / min-relay floor.
- **Mode** — `historical`, `mempool`, or `blend` (which data source the
  estimator is using).
- **Confidence** — `high` (green) / `medium` (yellow) / `low` (red) for
  the High tier specifically.

#### UTXO + Network (split)

**UTXO (left half):**
- **UTXOs** — total unspent outputs.
- **Total** — sum of UTXO values (BTC).
- **Supply** — fraction of the 21M cap. Asymptotic; never reaches 100%.
- **Age distribution** — sparkline by UTXO age: <1h, 1h–1d, 1d–1w,
  1w–1m, 1m–3m, 3m–1y, 1y–3y, 3y+.

**Network (right half):**
- **Peers** — inbound and outbound counts.

#### Peers table
Same controls as IBD's table; columns differ:

| Column | Meaning |
|---|---|
| **Addr** | Peer IP:port. |
| **Agent** | Subversion. |
| **Height** | Peer's best-known block height. |
| **Recv** | Total bytes transferred with this peer. |

#### Services row

A single line summarising satd's wallet-server surfaces, sourced from
`getserverstatus` and `getindexinfo`:

```
addr-idx <state>   esplora <state>   electrum <state>
```

**`addr-idx` states:**

| Display | Meaning |
|---|---|
| `⬤ synced` (green) | Address-history index is at tip. Esplora and Electrum are safe to serve history. |
| `⬤ syncing` (yellow) | Backfill in progress. Address queries may return partial history. |
| `⬤ backfill pass N/2 XX% (C/S) ETA …` (green) | Active backfill with progress. `C/S` is cursor / snapshot height. |
| `⬤ backfill paused …` (yellow) | Backfill paused. Resume with `sat-cli resumeindex address`. |
| `⬭ backfill FAILED — <err>` (red) | Backfill errored. Check `journalctl` / satd logs. |
| `⬭ off` (gray) | Address index disabled (`-addressindex=0`). |
| `⬭ -` (dim) | Status unknown — older satd, transient RPC error. |

**`esplora` and `electrum` states:**

| Display | Meaning |
|---|---|
| `⬭ <bind:port>` (green) | Bound and serving. |
| `(tls <bind:port>)` (cyan) | Electrum TLS bind, additional column. |
| `⬭ off` (gray) | Disabled in config or auto-disabled (e.g. address index off). |
| `⬭ -` (dim) | Unknown. |

#### Footer
Keybindings hint and an unclean-shutdown indicator (`⚠ unclean shutdown`)
if `last_shutdown` from `getsysteminfo` is dirty.

### Mempool view (`3`)

Drill-down on unconfirmed transactions. Five panels.

#### Title bar
Health dot, uptime.

#### Summary strip
- **Txs** — unconfirmed transaction count.
- **Bytes** — total mempool bytes.
- **Min / Max fees** — feerate range across mempool entries.
- **Δ last Ns** — entries added / removed in the last polling window.

#### Feerate histogram
Bars per feerate bucket (`1–2`, `2–5`, `5–10`, `10–20`, `20–50`,
`50–100`, `100–200`, `200–500`, `500+` sat/vB) with vbyte counts.
Bars are coloured by fee tier so the visual matches the Steady view's
**Fees** panel.

#### Trend + Top-N (split)

**Trend (left):** sparklines for Bytes, Txs, MinFee over ~40 minutes.

**Top-N (right):** scrollable table of the top 50 unconfirmed txs by
ancestor feerate.

| Column | Meaning |
|---|---|
| `#` | Rank within top 50. |
| `vsize` | Virtual size (vbytes). |
| `anc sat/vB` | Ancestor-adjusted effective feerate. Accounts for CPFP — a low-fee child gets pulled in by a high-fee parent. |
| `A/D` | Ancestor count / descendant count (chain depth in either direction). |
| `age` | Time since the tx entered the mempool. |

`Up` / `Down` scroll.

#### Footer
Keybindings.

### Chain view (`4`)

Long-horizon information that doesn't change every block. Three rows of
two panels each.

#### Halvings | Retarget

**Halvings:**
- **Subsidy epoch** — index (0 = pre-first-halving).
- **Subsidy** — current block reward in BTC. Formula `50 >> halvings`,
  saturates at 0 after halving 64.
- **Halving in** — blocks until the next halving.
- **Halving ETA** — estimated wall-clock time at the 10-min target.
- Progress bar through the current 210,000-block subsidy era.

**Retarget:**
- **Blocks to retarget** — blocks until the next 2,016-block boundary.
- **Retarget ETA** — wall-clock estimate at 10-min target.
- **Block time (epoch)** — observed average seconds per block within the
  current 2,016-block epoch. Empty at the start of an epoch.
- **Δ Est** — predicted difficulty adjustment at the next retarget,
  clamped to ±300% (Bitcoin's hard limit). Positive = blocks are coming
  in faster than the 10-min target → difficulty will rise.
- Progress bar through the current 2,016-block epoch.

#### Supply | Chain Security

**Supply:**
- **Issued** — BTC currently in the UTXO set.
- **% issued** — fraction of the 21M cap.
- **Remaining** — `21M − issued`.
- **Inflation: realized / forward** — annualised issuance rate at the
  current subsidy and at the post-next-halving subsidy.

**Chain Security:**
- **Chain work** — cumulative work, in `log₂(work)` bits. Computed from
  `chainwork` (which is a 256-bit hex string in the RPC) without
  materialising the full integer.
- **Rewrite at hashrate** — wall-clock seconds for the current network
  hashrate to redo the entire chain's work. Formula `2^(bits − log₂(hps))`.
  This is a back-of-envelope rewrite cost; reorgs of any meaningful depth
  are economically and physically infeasible.
- **Network hashrate** — same number as the Steady view's Chain panel.

#### Peer clients | Trivia

**Peer clients:** distribution of peers by user-agent string. Top 5
agents, plus an "other" bucket. Useful for spotting an unusually
homogeneous peer set or an unexpected dominant client.

**Trivia:** subsidy era name, halving date, next halving block height.
Light reading.

## Modal overlays

Modals are drawn over the active view. `Esc` or the toggle key closes
them.

### Help (`h` / `?`)
Context-sensitive keybindings for the active view.

### Reorg history (`r`)
Last 7 days of reorg events from `getreorghistory`. Up to 40 entries.

| Column | Meaning |
|---|---|
| **depth** | Blocks displaced. Coloured: 1 = yellow, 2–3 = light red, 4+ = red. |
| **fork height** | Height at which the old and new chains diverged. |
| **old tip / new tip** | Block hashes, truncated. |
| **−N +M blocks** | Disconnected vs. reconnected counts. |
| **age** | Time since the reorg. |

A persistent file copy lives at `$datadir/<network>/reorg.log` (the
network-specific datadir subdirectory; directly under `$datadir` only on
mainnet) and is written by satd regardless of TUI state — the modal is a
viewer, not the source of truth.

### Warnings
Centred 80% × 70% overlay that appears automatically when there are
visible warnings from `getwarnings`. Border colour is red (any Error
severity present) or yellow (Warn-only).

| Field | Meaning |
|---|---|
| `[ERROR]` / `[WARN]` | Severity. |
| **ID** | Warning identifier (cyan). |
| `first seen Ns ago · ×count` | Age and recurrence. |
| **message** | Human-readable description. |

- **`a`** acknowledges and dismisses every currently visible warning for
  this session.
- **`w`** re-shows everything previously dismissed.

Dismissal is per-session. If satd clears a warning ID and re-emits it,
the modal reappears.

## Keybindings

| Key | Effect |
|---|---|
| `q` | Quit. Closes Help / Reorg modal first if open. |
| `Ctrl-C` | Quit. |
| `h` or `?` | Toggle Help overlay. |
| `r` | Toggle Reorg history. |
| `1` | IBD view (or back to auto). |
| `2` | Steady view (or back to auto). |
| `3` | Mempool view (or back to auto). |
| `4` | Chain view (or back to auto). |
| `a` | Acknowledge all visible warnings. |
| `w` | Re-show dismissed warnings. |
| `Esc` | Close Help or Reorg modal. |
| `Up` / `Down` | Scroll peers (IBD / Steady / Chain) or top-N (Mempool). |

## Polling and refresh

The TUI does not push commands to satd; it polls. The render loop runs
every 250 ms regardless of polling state, so the UI stays responsive
even when RPC is slow.

| Cadence | RPC calls |
|---|---|
| **1.5 s** | `getblockchaininfo`, `getpeerinfo`, `getmempoolinfo`, `getconnectioncount`, `getsysteminfo`, `getwarnings`. |
| **3 s** | `getibdprogress` (during IBD only — heavy: full bitmap and per-peer breakdown). |
| **~5 s** | `getindexinfo`, `getserverstatus`, plus the steady-state batch (`estimatefees`, `getmininginfo`, `getchaintxstats`, `uptime`, `getblockstats`, `getrawmempool` (verbose), `gettxoutsetinfo`, `getreorghistory`, `getmempoolhistory`). |
| **per epoch** | `getblockhash` + `getblockheader` to anchor the current 2,016-block epoch's start time. Refreshed only when the epoch floor advances. |

If a steady-state RPC has not returned within ~3 s, the title bar shows
`stale`. The view continues to render; the UI just makes it visible
that what you are looking at is older than the polling cadence implies.

## Failure modes

| What you see | What it means |
|---|---|
| `Connecting to satd…` | RPC unreachable, returning errors, or only `getstartupinfo` is responding. |
| Auth retry, then `Connecting…` | Cookie was rotated and the second attempt also failed — common during a satd restart. Will recover. |
| Stale indicator (`✕ stale`) | Polling is alive but a recent call hasn't returned. Investigate if persistent. |
| Empty / dashed fields (`—`, `-`) | The RPC backing that field hasn't returned yet, or returned an error. |
| Warnings modal won't dismiss | The warning is still active in satd. Dismissal is per-session; resolve at the source. |

The TUI never panics on RPC errors — it surfaces them visibly and keeps
polling.

## See also

- [Observability & Metrics](observability.md) and [Configuration, Tuning &
  Reload](configuration.md) — the broader operator surfaces (CLI, RPC,
  observability, tuning).
- [`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md) — what satd does
  differently from Bitcoin Core.
- [Esplora REST API](esplora.md) — Esplora REST endpoint reference.
- `sat-cli help` — every JSON-RPC method exposed by satd, including the
  ones the TUI uses.
