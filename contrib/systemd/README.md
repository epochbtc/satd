# systemd integration

Two units ship here:

- **`satd.service`** — single-instance unit for one satd daemon on the
  default datadir (`/var/lib/satd`). The right choice for a host that
  runs only one network.
- **`satd@.service`** — template unit for per-network instances on the
  same host (`satd@mainnet`, `satd@signet`, …). Each instance gets its
  own `/var/lib/satd/<network>` datadir and reads
  `/etc/default/satd@<network>` for per-instance flags.

See the comment block at the top of each unit file for install steps.
The user-facing operator guide lives in
[`docs/manual/src/packaging.md`](../../docs/manual/src/packaging.md).

## Lifecycle behaviour

Both units use `Type=notify` with `NotifyAccess=main`:

- **Startup heartbeat.** During long-running startup phases like
  `--reindex-chainstate`, satd emits `EXTEND_TIMEOUT_USEC=120000000`
  plus `STATUS=<phase: progress>` every 30s. The unit ships with
  `TimeoutStartSec=3min` — a finite budget that the heartbeat keeps
  extending. An actively-progressing reindex never hits the wall; a
  pre-ready wedge with no heartbeat for >120s gets killed. (An
  `infinity` startup timeout would defeat the heartbeat — there's
  nothing to extend, so silence has no consequence.)
- **Post-ready watchdog.** After `notify_ready()`, satd ticks
  `WATCHDOG=1` every `WatchdogSec/2` (= 60s at the default 120s
  setting), gated by non-blocking subsystem probes. A wedged tip lock
  or stuck tokio runtime suppresses the ping; systemd kills the unit
  at the deadline and `Restart=always` brings it back. The 120s
  window absorbs legitimate long-held write locks (slow compaction,
  large reorg connects); operators on slow hardware can extend
  further via a drop-in (`/etc/systemd/system/satd.service.d/
  watchdog.conf` with `[Service]\nWatchdogSec=300s`). Complements
  the chain-level stall watchdog in `node/src/stall_watchdog.rs`,
  which catches "alive but chain not advancing."
- **Shutdown.** `notify_stopping()` fires before the blocking RocksDB
  flush so `systemctl status` reads "deactivating" immediately rather
  than staring at "active" for the full `TimeoutStopSec`.

## Per-instance network selection (`satd@.service`)

Network flag for `satd@<instance>` is resolved in this order:

1. **`SATD_NETWORK`** from `/etc/default/satd@<instance>` (or the
   shared `/etc/default/satd`), if set. Lets you run an instance with
   a custom name (e.g. `satd@bench` on mainnet) by setting
   `SATD_NETWORK=mainnet` in the per-instance EnvironmentFile.
2. **Instance name `%i`** otherwise. So `satd@signet` runs `--signet`
   with no explicit env var.

Recognized values: `mainnet`, `signet`, `testnet`, `testnet3`,
`testnet4`, `regtest`. **Anything else fails fast at start** — a
typo like `satd@singet` will refuse to start rather than silently
launch mainnet under the wrong datadir name.

## OpenRC and runit equivalents

The same lifecycle semantics ship for OpenRC (`contrib/openrc/`) and
runit (`contrib/runit/`) — they don't carry the `Type=notify` /
`WatchdogSec=` machinery (those are systemd-specific) but provide the
same start / stop / restart behaviour, hardening, and resource
limits where the supervisor supports them.
