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
[`docs/PACKAGING.md`](../../docs/PACKAGING.md).

## Lifecycle behaviour

Both units use `Type=notify` with `NotifyAccess=main`:

- **Startup heartbeat.** During long-running startup phases like
  `--reindex-chainstate`, satd emits `EXTEND_TIMEOUT_USEC=120000000`
  plus `STATUS=<phase: progress>` every 30s. `TimeoutStartSec=infinity`
  is fine — the heartbeat IS the liveness check.
- **Post-ready watchdog.** After `notify_ready()`, satd ticks
  `WATCHDOG=1` every `WatchdogSec/2` (= 30s at the default 60s
  setting), gated by non-blocking subsystem probes. A wedged tip lock
  or stuck tokio runtime suppresses the ping; systemd kills the unit
  at the deadline and `Restart=always` brings it back. Complements the
  chain-level stall watchdog in `node/src/stall_watchdog.rs`, which
  catches "alive but chain not advancing."
- **Shutdown.** `notify_stopping()` fires before the blocking RocksDB
  flush so `systemctl status` reads "deactivating" immediately rather
  than staring at "active" for the full `TimeoutStopSec`.

## OpenRC and runit equivalents

The same lifecycle semantics ship for OpenRC (`contrib/openrc/`) and
runit (`contrib/runit/`) — they don't carry the `Type=notify` /
`WatchdogSec=` machinery (those are systemd-specific) but provide the
same start / stop / restart behaviour, hardening, and resource
limits where the supervisor supports them.
