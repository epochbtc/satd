# sat-tui

`sat-tui` is the operator dashboard for satd: a curses-style terminal UI
that connects over JSON-RPC and shows what the node is doing. It is
read-only. The TUI cannot change node state. Bitcoin Core ships no
equivalent surface.

This document is the reference for what the TUI shows. It is not a
walkthrough. For guidance on what to look at first, see
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

If the cookie rotates while the TUI is running, for example because satd
restarted, the RPC client re-reads the cookie file and retries once. If
the retry also fails, the TUI falls back to the "Connecting to satd…"
splash.

### Other CLI flags

| Flag | Default | Meaning |
|---|---|---|
| `--rpcconnect <host>` | `127.0.0.1` | RPC host. |
| `--rpcport <port>` | per-network default | Override the auto-detected port. |
| `--datadir <path>` | `~/.bitcoin` | Used to locate the cookie file. |
| `--rpcuser <user>` | (none) | Userpass auth (with `--rpcpassword`). |
| `--rpcpassword <pass>` | (none) | Userpass auth (with `--rpcuser`). |
| `--rpccookiefile <path>` | auto | Override cookie path. |

The TUI exits cleanly on `q` or `Ctrl-C` and restores the terminal mode.

## Connection states

Before any view is shown, `sat-tui` is in one of three connection states:

- **"Connecting to satd…"** (yellow, centered): RPC is unreachable, or
  has returned only failures so far. Common during cold start, satd
  restart, or misconfigured auth.
- **Startup splash**: satd is up but still starting (header scan,
  reindex, address-index backfill). The splash is sourced from satd's
  `getstartupinfo` RPC; see [Startup splash](#startup-splash) below.
- **Active view**: `getblockchaininfo` succeeded and one of the four
  main views is rendered.

A red `✕ stale` indicator in the title bar means the last successful
poll is more than about 3 seconds old. It means RPC is degraded right
now. The TUI recovers on its own when polling resumes.

## Views

There are four main views, plus a startup splash and three modal
overlays.

The active view is auto-selected from chain state (`is_ibd`): the IBD
view during initial block download, the Steady view once synced. Press
`1` / `2` / `3` / `4` to force a view. Press the same key again to
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
| **Rate** | Items per second: blocks, headers, or whatever the phase iterates over. |
| **ETA** | Estimated remaining time for this phase only, not whole startup. |

ETAs cover one phase at a time because per-item costs differ sharply
between phases. During a reindex, the header scan and the block replay
proceed at unrelated rates, so a whole-startup estimate would mislead
until the replay dominates.

### IBD view (`1`)

Shown while the node is in initial block download. Five panels stacked
vertically:

#### Title bar
Chain name, satd version, `is_ibd` indicator.

#### Progress block
- **Blocks / target**: connected blocks vs. the highest block any peer
  has advertised.
- **blk/s**: blocks connected per second, EMA-smoothed.
- **hdr/s**: headers received per second.
- **ETA**: server-side estimate from satd's `getibdprogress` RPC.
  Per-block validation cost varies about 50× across history, from early
  empty blocks to modern weight-bound blocks. A naive "blocks remaining
  ÷ blk/s" calculation is wildly wrong, especially in the first few
  hundred thousand blocks.
- **Peers**: connected peer count.

#### Block map
A bitmap of download state per block group (one cell ≈ many blocks):

| Glyph | Color | Meaning |
|---|---|---|
| `█` | green | **Connected**: validated and in the chain. |
| `░` | cyan | **Downloaded**: on disk, waiting for sequential connection. |
| `▓` | yellow | **In flight**: requested from a peer, not yet received. |
| `·` | dim | **Pending**: queued for download, not yet requested. |

A healthy IBD shows a leading wave of `█` followed by `░`, with a
narrow `▓` band at the frontier. Long stretches of `▓` mean a peer is
slow or unresponsive. Long stretches of `·` mean the node is
bandwidth-bound or short on peers.

#### Sync rate + stats

Two sparklines (about 90 seconds of history):

- **blk/s connected** (yellow): rate of blocks fully validated.
- **blk/s downloaded** (cyan): rate of blocks pulled from peers, all
  peers summed.

Plus a stats panel: Headers, Connected, Stored, In-Flight, Remaining.

#### Peers table

| Column | Meaning |
|---|---|
| **Addr** | Peer IP and port. |
| **Agent** | Subversion string (`/Satoshi:25.1.0/`, `/satd:0.1.0/`, …). |
| **Recv** | Blocks received from this peer this session. |
| **Assigned** | Blocks currently assigned to this peer for download. |
| **Rate** | Per-peer blk/s, EMA-smoothed. Shows `—` below 0.1 blk/s. |

`Up` / `Down` highlights a row.

### Steady view (`2`)

Default view once `is_ibd=false`. Six stacked panels.

#### Title bar
Health dot, uptime.

| Symbol | Meaning |
|---|---|
| `● ready` (green) | Polling is fresh, node is at tip. |
| `○ syncing` (yellow) | Polling is fresh, node is catching up a small lag. |
| `✕ stale` (red) | Last poll is older than about 3 s. RPC may be degraded. |

#### Chain + Latest block (split)

Chain (left half):

- **Height**: current tip height.
- **Difficulty**: raw difficulty value.
- **Hash Rate**: network hashrate from `getmininginfo` (H/s).
- **Last Block**: seconds since the tip block's timestamp. More than an
  hour is unusual.

Latest block (right half):

- **Hash**: tip hash, truncated.
- **Txs**: transaction count.
- **Size / Weight**: bytes / weight units.
- **Fees**: total miner fees collected (BTC).
- **Avg Rate**: average effective fee rate across all txs (sat/vB).

#### Mempool + Fees (split)

Mempool (left half):

- **Txs**: unconfirmed transactions.
- **Size**: total bytes.
- **Min Rate**: current mempool minimum fee. `0.0` is the default, the
  min-relay floor of about 1 sat/vB. A non-zero value means the mempool
  is full and is evicting low-fee txs. New txs need at least this rate
  to enter.
- **Tx Rate**: recent tx-entry rate from `getchaintxstats` (tx/s).
- **Size distribution**: sparkline of vbyte buckets (0, 100, 250, 500,
  1k, 5k, 10k, 50k+).

Fees (right half), fee tier estimates from `estimatefees`
(mempool.space convention):

- **High**: next-block target (1-block confirmation).
- **Medium**: about 30 minutes (3-block target).
- **Low**: about 1 hour (6-block target).
- **None**: economy / min-relay floor.
- **Mode**: the estimator's data source: `historical`, `mempool`, or
  `blend`.
- **Confidence**: `high` (green) / `medium` (yellow) / `low` (red), for
  the High tier specifically.

#### UTXO + Network (split)

UTXO (left half):

- **UTXOs**: total unspent outputs.
- **Total**: sum of UTXO values (BTC).
- **Supply**: fraction of the 21M cap. Asymptotic; never reaches 100%.
- **Age distribution**: sparkline by UTXO age: <1h, 1h–1d, 1d–1w,
  1w–1m, 1m–3m, 3m–1y, 1y–3y, 3y+.

Network (right half):

- **Peers**: inbound and outbound counts.

#### Peers table
Same controls as IBD's table; columns differ:

| Column | Meaning |
|---|---|
| **Addr** | Peer IP:port. |
| **Agent** | Subversion. |
| **Height** | Peer's best-known block height. |
| **Recv** | Total bytes transferred with this peer. |

#### Services row

A single line summarizing satd's wallet-server surfaces, sourced from
`getserverstatus` and `getindexinfo`:

```
addr-idx <state>   esplora <state>   electrum <state>
```

`addr-idx` states:

| Display | Meaning |
|---|---|
| `⬤ synced` (green) | Address-history index is at tip. Esplora and Electrum are safe to serve history. |
| `⬤ syncing` (yellow) | Backfill in progress. Address queries may return partial history. |
| `⬤ backfill pass N/2 XX% (C/S) ETA …` (green) | Active backfill with progress. `C/S` is cursor / snapshot height. |
| `⬤ backfill paused …` (yellow) | Backfill paused. Resume with `sat-cli resumeindex address`. |
| `⬭ backfill FAILED — <err>` (red) | Backfill errored. Check `journalctl` or the satd logs. |
| `⬭ off` (gray) | Address index disabled (`-addressindex=0`). |
| `⬭ -` (dim) | Status unknown: older satd, or a transient RPC error. |

`esplora` and `electrum` states:

| Display | Meaning |
|---|---|
| `⬭ <bind:port>` (green) | Bound and serving. |
| `(tls <bind:port>)` (cyan) | Electrum TLS bind, additional column. |
| `⬭ off` (gray) | Disabled in config, or auto-disabled (e.g. address index off). |
| `⬭ -` (dim) | Unknown. |

#### Footer
Keybindings hint, plus an unclean-shutdown indicator
(`⚠ unclean shutdown`) if `last_shutdown` from `getsysteminfo` is dirty.

### Mempool view (`3`)

Drill-down on unconfirmed transactions. Five panels.

#### Title bar
Health dot, uptime.

#### Summary strip
- **Txs**: unconfirmed transaction count.
- **Bytes**: total mempool bytes.
- **Min / Max fees**: feerate range across mempool entries.
- **Δ last Ns**: entries added and removed in the last polling window.

#### Feerate histogram
Bars per feerate bucket (`1–2`, `2–5`, `5–10`, `10–20`, `20–50`,
`50–100`, `100–200`, `200–500`, `500+` sat/vB) with vbyte counts.
Bars are colored by fee tier, matching the Steady view's Fees panel.

#### Trend + Top-N (split)

Trend (left): sparklines for Bytes, Txs, MinFee over about 40 minutes.

Top-N (right): scrollable table of the top 50 unconfirmed txs by
ancestor feerate.

| Column | Meaning |
|---|---|
| `#` | Rank within top 50. |
| `vsize` | Virtual size (vbytes). |
| `anc sat/vB` | Ancestor-adjusted effective feerate. Accounts for CPFP: a low-fee child gets pulled in by a high-fee parent. |
| `A/D` | Ancestor count / descendant count (chain depth in either direction). |
| `age` | Time since the tx entered the mempool. |

`Up` / `Down` scroll.

#### Footer
Keybindings.

### Chain view (`4`)

Long-horizon information that does not change every block. Three rows
of two panels each.

#### Halvings | Retarget

Halvings:

- **Subsidy epoch**: index (0 = pre-first-halving).
- **Subsidy**: current block reward in BTC. Formula `50 >> halvings`,
  saturates at 0 after halving 64.
- **Halving in**: blocks until the next halving.
- **Halving ETA**: estimated wall-clock time at the 10-minute target.
- Progress bar through the current 210,000-block subsidy era.

Retarget:

- **Blocks to retarget**: blocks until the next 2,016-block boundary.
- **Retarget ETA**: wall-clock estimate at the 10-minute target.
- **Block time (epoch)**: observed average seconds per block within the
  current 2,016-block epoch. Empty at the start of an epoch.
- **Δ Est**: predicted difficulty adjustment at the next retarget,
  clamped to ±300% (Bitcoin's hard limit). A positive value means
  blocks arrive faster than the 10-minute target, so difficulty will
  rise.
- Progress bar through the current 2,016-block epoch.

#### Supply | Chain Security

Supply:

- **Issued**: BTC currently in the UTXO set.
- **% issued**: fraction of the 21M cap.
- **Remaining**: `21M − issued`.
- **Inflation: realized / forward**: annualized issuance rate at the
  current subsidy and at the post-next-halving subsidy.

Chain Security:

- **Chain work**: cumulative work, in `log₂(work)` bits. Computed from
  the RPC's 256-bit `chainwork` hex string without materializing the
  full integer.
- **Rewrite at hashrate**: wall-clock seconds for the current network
  hashrate to redo the entire chain's work. Formula
  `2^(bits − log₂(hps))`. This is a back-of-envelope rewrite cost;
  reorgs of any meaningful depth are economically and physically
  infeasible.
- **Network hashrate**: same number as the Steady view's Chain panel.

#### Peer clients | Trivia

Peer clients: distribution of peers by user-agent string. Top 5 agents,
plus an "other" bucket. Useful for spotting an unusually homogeneous
peer set or an unexpected dominant client.

Trivia: subsidy era name, halving date, next halving block height.
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
| **depth** | Blocks displaced. Colored: 1 = yellow, 2–3 = light red, 4+ = red. |
| **fork height** | Height at which the old and new chains diverged. |
| **old tip / new tip** | Block hashes, truncated. |
| **−N +M blocks** | Disconnected vs. reconnected counts. |
| **age** | Time since the reorg. |

A persistent copy lives at `$datadir/<network>/reorg.log`, in the
network-specific datadir subdirectory. On mainnet the file sits
directly under `$datadir`. satd writes this log whether or not the TUI
is running; the modal is a viewer of it.

### Warnings
A centered overlay (80% × 70%) that appears automatically when
`getwarnings` reports visible warnings. The border is red if any
warning has Error severity, otherwise yellow.

| Field | Meaning |
|---|---|
| `[ERROR]` / `[WARN]` | Severity. |
| **ID** | Warning identifier (cyan). |
| `first seen Ns ago · ×count` | Age and recurrence. |
| **message** | Human-readable description. |

Press `a` to acknowledge and dismiss every currently visible warning
for this session. Press `w` to re-show everything previously dismissed.

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
| **3 s** | `getibdprogress`. During IBD only; the reply is heavy (full bitmap and per-peer breakdown). |
| **~5 s** | `getindexinfo`, `getserverstatus`, plus the steady-state batch (`estimatefees`, `getmininginfo`, `getchaintxstats`, `uptime`, `getblockstats`, `getrawmempool` (verbose), `gettxoutsetinfo`, `getreorghistory`, `getmempoolhistory`). |
| **per epoch** | `getblockhash` + `getblockheader` to anchor the current 2,016-block epoch's start time. Refreshed only when the epoch floor advances. |

If a steady-state RPC has not returned within about 3 s, the title bar
shows `stale`. The view continues to render; the indicator shows that
the data on screen is older than the polling cadence implies.

## Failure modes

| What you see | What it means |
|---|---|
| `Connecting to satd…` | RPC unreachable, returning errors, or only `getstartupinfo` is responding. |
| Auth retry, then `Connecting…` | The cookie rotated and the retry also failed, which is common during a satd restart. Recovers on its own. |
| Stale indicator (`✕ stale`) | Polling is alive but a recent call has not returned. Investigate if persistent. |
| Empty / dashed fields (`—`, `-`) | The RPC backing that field has not returned yet, or returned an error. |
| Warnings modal won't dismiss | The warning is still active in satd. Dismissal is per-session; resolve at the source. |

The TUI does not panic on RPC errors. It shows them and keeps polling.

## See also

- [Observability & Metrics](observability.md) and [Configuration, Tuning &
  Reload](configuration.md): the broader operator surfaces (CLI, RPC,
  observability, tuning).
- [`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md):
  what satd does differently from Bitcoin Core.
- [Esplora REST API](esplora.md): Esplora REST endpoint reference.
- `sat-cli help`: every JSON-RPC method exposed by satd, including the
  ones the TUI uses.
