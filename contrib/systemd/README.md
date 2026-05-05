# systemd integration

`satd.service` is a unit suitable for distro packages and hand-rolled
deployments alike. It runs satd as a system user with the standard
hardening directives applied (read-only /, private /tmp, restricted
syscalls).

See the comment block at the top of the unit file for install steps.
The user-facing operator guide for service ergonomics lives in
[`docs/PACKAGING.md`](../../docs/PACKAGING.md).

## Type=simple → Type=notify

The unit ships as `Type=simple` because satd does not yet call
`sd_notify(READY=1)`. The intended behaviour — and what a future PR
will switch to — is `Type=notify` with `NotifyAccess=main`, so systemd
considers the unit started only after RocksDB has finished opening.

Operators who want notify-style behaviour today can use a wrapper that
polls `/healthz` (when `--metricsport=` is configured) and call
`systemd-notify --ready` from a `ExecStartPost=` shim. This is a
short-term workaround; the in-process `sd_notify` integration is the
intended end state.
