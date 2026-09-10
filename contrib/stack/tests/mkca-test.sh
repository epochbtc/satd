#!/bin/bash
# Tests for contrib/stack/tls/mkca.sh.
#
# The script runs on every container start and on a systemd timer, so the
# properties under test are mostly about what it does NOT do: it must not
# reissue a healthy certificate, must not rotate the CA, and must not leave
# a half-written state that a later run would trust. Those are exactly the
# failures that stay invisible until a client's imported CA stops matching.
#
# openssl is the only dependency.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MKCA="$HERE/../tls/mkca.sh"
[[ -x "$MKCA" ]] || { echo "not executable: $MKCA" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
pass() { echo "ok   — $1"; }
fail() { echo "FAIL — $1"; [[ $# -lt 2 ]] || sed 's/^/       /' <<< "$2"; FAILURES=$((FAILURES + 1)); }

assert_eq() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then pass "$name"
    else fail "$name" "expected: $expected
actual:   $actual"; fi
}

# Detection of live interface addresses is off in every case here: the SAN
# set must be a function of the arguments alone, or the assertions below
# would depend on whatever addresses the test machine happens to hold.
mkca() { "$MKCA" --no-detect-ips "$@"; }

sans_of() { openssl x509 -in "$1" -noout -ext subjectAltName | tail -n +2 | tr -d ' \n'; }
serial_of() { openssl x509 -in "$1" -noout -serial | cut -d= -f2; }

# --- issuance --------------------------------------------------------------
D="$WORK/basic"
mkca --dir "$D" --hostname satd-test --quiet > "$WORK/log" 2>&1 || fail "first run exits 0" "$(cat "$WORK/log")"

for f in ca.key ca.crt leaf.key leaf.crt fullchain.crt leaf.sans; do
    [[ -s "$D/$f" ]] && pass "creates $f" || fail "creates $f"
done

if openssl verify -CAfile "$D/ca.crt" "$D/leaf.crt" > /dev/null 2>&1; then
    pass "leaf verifies against the CA"
else
    fail "leaf verifies against the CA"
fi

# fullchain is what satd is pointed at; it must actually contain both certs,
# or a client that trusts the CA still sees an incomplete chain.
assert_eq "fullchain holds leaf + CA" "2" "$(grep -c 'BEGIN CERTIFICATE' "$D/fullchain.crt")"

sans="$(sans_of "$D/leaf.crt")"
for expected in "DNS:localhost" "DNS:satd-test" "DNS:satd-test.local" "IPAddress:127.0.0.1"; do
    [[ "$sans" == *"$expected"* ]] && pass "SAN includes $expected" \
        || fail "SAN includes $expected" "got: $sans"
done

# ::1 renders as the expanded form in openssl's text output.
[[ "$sans" == *"IPAddress:0:0:0:0:0:0:0:1"* ]] && pass "SAN includes ::1" \
    || fail "SAN includes ::1" "got: $sans"

# The certificate has to be usable as a TLS *server* credential; an EKU
# mismatch is the kind of thing that verifies fine with `openssl verify` and
# then fails in every real client.
eku="$(openssl x509 -in "$D/leaf.crt" -noout -ext extendedKeyUsage | tail -n +2 | tr -d ' \n')"
assert_eq "leaf EKU is serverAuth" "TLSWebServerAuthentication" "$eku"

bc="$(openssl x509 -in "$D/ca.crt" -noout -ext basicConstraints | tail -n +2 | tr -d ' \n')"
[[ "$bc" == *"CA:TRUE"* ]] && pass "CA cert is marked CA:TRUE" || fail "CA cert is marked CA:TRUE" "got: $bc"

bc_leaf="$(openssl x509 -in "$D/leaf.crt" -noout -ext basicConstraints | tail -n +2 | tr -d ' \n')"
[[ "$bc_leaf" == *"CA:FALSE"* ]] && pass "leaf is marked CA:FALSE" || fail "leaf is marked CA:FALSE" "got: $bc_leaf"

assert_eq "CA key is 0600 by default" "600" "$(stat -c %a "$D/ca.key")"
assert_eq "leaf key is 0600 by default" "600" "$(stat -c %a "$D/leaf.key")"
assert_eq "CA cert is world-readable" "644" "$(stat -c %a "$D/ca.crt")"

# --- idempotence -----------------------------------------------------------
ca_serial_before="$(serial_of "$D/ca.crt")"
leaf_serial_before="$(serial_of "$D/leaf.crt")"
ca_key_before="$(sha256sum < "$D/ca.key")"

mkca --dir "$D" --hostname satd-test --quiet > /dev/null 2>&1
assert_eq "re-running does not reissue the leaf" "$leaf_serial_before" "$(serial_of "$D/leaf.crt")"
assert_eq "re-running does not rotate the CA" "$ca_serial_before" "$(serial_of "$D/ca.crt")"
assert_eq "re-running does not touch the CA key" "$ca_key_before" "$(sha256sum < "$D/ca.key")"

# --- reissue triggers ------------------------------------------------------
mkca --dir "$D" --hostname satd-test --extra-name extra.example --quiet > /dev/null 2>&1
new_serial="$(serial_of "$D/leaf.crt")"
[[ "$new_serial" != "$leaf_serial_before" ]] && pass "a new SAN reissues the leaf" \
    || fail "a new SAN reissues the leaf"
assert_eq "a new SAN does not rotate the CA" "$ca_serial_before" "$(serial_of "$D/ca.crt")"
[[ "$(sans_of "$D/leaf.crt")" == *"DNS:extra.example"* ]] && pass "the new SAN is present" \
    || fail "the new SAN is present"

# Dropping the SAN again must also reissue — the check has to be a set
# comparison, not "did anything get added".
mkca --dir "$D" --hostname satd-test --quiet > /dev/null 2>&1
[[ "$(sans_of "$D/leaf.crt")" != *"DNS:extra.example"* ]] && pass "a removed SAN reissues the leaf" \
    || fail "a removed SAN reissues the leaf"

serial_before_force="$(serial_of "$D/leaf.crt")"
mkca --dir "$D" --hostname satd-test --force --quiet > /dev/null 2>&1
[[ "$(serial_of "$D/leaf.crt")" != "$serial_before_force" ]] && pass "--force reissues the leaf" \
    || fail "--force reissues the leaf"

# A leaf inside the renewal window must be replaced. Issued for 10 days with
# a 30-day window, so the very next run has to renew it.
D2="$WORK/expiring"
mkca --dir "$D2" --hostname short-lived --days 10 --renew-within 30 --quiet > /dev/null 2>&1
short_serial="$(serial_of "$D2/leaf.crt")"
mkca --dir "$D2" --hostname short-lived --days 10 --renew-within 30 --quiet > /dev/null 2>&1
[[ "$(serial_of "$D2/leaf.crt")" != "$short_serial" ]] && pass "a leaf inside the renewal window is renewed" \
    || fail "a leaf inside the renewal window is renewed"
# ... and the renewal must not have rotated the CA out from under clients.
assert_eq "renewal keeps the same CA" "1" "$(openssl verify -CAfile "$D2/ca.crt" "$D2/leaf.crt" > /dev/null 2>&1 && echo 1 || echo 0)"

# --- CA rotation is deliberate ---------------------------------------------
# `rm ca.*` is the documented way to rotate. The stale leaf must not survive
# it: a leaf signed by a CA that no longer exists verifies nowhere.
D3="$WORK/rotate"
mkca --dir "$D3" --hostname rotate-me --quiet > /dev/null 2>&1
old_leaf="$(serial_of "$D3/leaf.crt")"
rm -f "$D3/ca.key" "$D3/ca.crt"
mkca --dir "$D3" --hostname rotate-me --quiet > /dev/null 2>&1
[[ "$(serial_of "$D3/leaf.crt")" != "$old_leaf" ]] && pass "removing the CA reissues the leaf too" \
    || fail "removing the CA reissues the leaf too"
if openssl verify -CAfile "$D3/ca.crt" "$D3/leaf.crt" > /dev/null 2>&1; then
    pass "the reissued leaf chains to the new CA"
else
    fail "the reissued leaf chains to the new CA"
fi

# --- flags -----------------------------------------------------------------
D4="$WORK/groupread"
mkca --dir "$D4" --hostname grp --group-readable --quiet > /dev/null 2>&1
assert_eq "--group-readable sets 0640 on the leaf key" "640" "$(stat -c %a "$D4/leaf.key")"

D5="$WORK/fqdn"
mkca --dir "$D5" --hostname node.example.com --quiet > /dev/null 2>&1
# An FQDN must not gain a `.local` suffix — `node.example.com.local` is not
# a name anything resolves, and it would be a permanent extra SAN.
[[ "$(sans_of "$D5/leaf.crt")" != *".com.local"* ]] && pass "an FQDN hostname gets no .local SAN" \
    || fail "an FQDN hostname gets no .local SAN" "got: $(sans_of "$D5/leaf.crt")"

if "$MKCA" --hostname x >/dev/null 2>&1; then
    fail "--dir is required"
else
    pass "--dir is required"
fi

# --- keys are per-install --------------------------------------------------
# Two installs must never share a CA key. This is the property that makes
# shipping the appliance image safe at all.
DA="$WORK/inst-a"; DB="$WORK/inst-b"
mkca --dir "$DA" --hostname same-name --quiet > /dev/null 2>&1
mkca --dir "$DB" --hostname same-name --quiet > /dev/null 2>&1
if [[ "$(sha256sum < "$DA/ca.key")" != "$(sha256sum < "$DB/ca.key")" ]]; then
    pass "two installs get different CA keys"
else
    fail "two installs get different CA keys"
fi

if [[ $FAILURES -ne 0 ]]; then
    echo "$FAILURES mkca test(s) failed" >&2
    exit 1
fi
echo "all mkca tests passed"
