#!/bin/bash
# mkca.sh — issue the per-install local CA and server certificate that every
# satd TLS surface presents.
#
# One script, three consumers: the compose stack's entrypoint
# (contrib/stack/satd/entrypoint.sh), the appliance's first boot
# (contrib/appliance/provision/20-tls.sh), and the Umbrel / StartOS packages.
# They must all produce certificates with the same shape, because the same
# client instructions ("export the CA, import it once") are printed by all
# three.
#
#   ca.crt / ca.key        the install's own CA — 10 years, EC P-256
#   leaf.crt / leaf.key    the server certificate every surface presents
#   fullchain.crt          leaf + CA, which is what satd is pointed at
#   leaf.sans              the SAN list the leaf was issued for (see below)
#
# ## Why a CA and a leaf, rather than one self-signed certificate
#
# The CA is what a client imports, once. Re-issuing the leaf — because the
# lease gave the box a new address, because the hostname changed, or because
# the year is up — then costs the user nothing: the CA they already trust
# signed the new leaf too. A bare self-signed certificate would have to be
# re-imported every time, and "accept this new certificate" prompts are
# exactly the habit an appliance should not be teaching.
#
# ## Idempotence
#
# Re-running this is the normal case: it runs on every container start and on
# a systemd timer. It reissues the leaf only when there is a reason to —
# the leaf is missing, expires within --renew-within days, or the SAN set has
# changed since it was issued (recorded in leaf.sans). Otherwise it does
# nothing and says so, so a restart loop cannot churn certificates.
#
# The CA is never reissued once it exists. Rotating it invalidates every
# client's imported trust, so that is a deliberate operator act: delete the
# directory.
#
# ## Nothing here ships in an image
#
# Both keys are generated at first run on the machine that will use them. A
# shipped CA key would be a shared private key on every download, which is
# not a CA at all. contrib/appliance's build asserts these files are absent
# from the built image.

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: mkca.sh --dir <path> [options]

  --dir <path>            Directory to hold the CA and leaf. Required.
  --hostname <name>       Primary name for the leaf (default: `hostname`).
  --extra-name <name>     Additional DNS SAN. Repeatable.
  --extra-ip <addr>       Additional IP SAN. Repeatable.
  --no-detect-ips         Do not add the machine's current addresses as SANs.
  --ca-days <n>           CA validity (default 3650).
  --days <n>              Leaf validity (default 365).
  --renew-within <n>      Reissue the leaf when fewer than n days remain
                          (default 30).
  --owner <user[:group]>  chown the generated files to this owner.
  --group-readable        Key mode 0640 instead of 0600 (needed when a
                          service runs as a different user in the owner's
                          group).
  --force                 Reissue the leaf even if the current one is fine.
  --quiet                 Only report actual changes.

Exit status is 0 whether or not anything was reissued; `--force` aside, the
script is safe to run on every start.
USAGE
}

DIR=""
HOSTNAME_ARG=""
EXTRA_NAMES=()
EXTRA_IPS=()
DETECT_IPS=1
CA_DAYS=3650
LEAF_DAYS=365
RENEW_WITHIN=30
OWNER=""
KEY_MODE=0600
FORCE=0
QUIET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) DIR="$2"; shift 2 ;;
        --hostname) HOSTNAME_ARG="$2"; shift 2 ;;
        --extra-name) EXTRA_NAMES+=("$2"); shift 2 ;;
        --extra-ip) EXTRA_IPS+=("$2"); shift 2 ;;
        --no-detect-ips) DETECT_IPS=0; shift ;;
        --ca-days) CA_DAYS="$2"; shift 2 ;;
        --days) LEAF_DAYS="$2"; shift 2 ;;
        --renew-within) RENEW_WITHIN="$2"; shift 2 ;;
        --owner) OWNER="$2"; shift 2 ;;
        --group-readable) KEY_MODE=0640; shift ;;
        --force) FORCE=1; shift ;;
        --quiet) QUIET=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "mkca.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -n "$DIR" ]] || { echo "mkca.sh: --dir is required" >&2; exit 2; }
command -v openssl >/dev/null || { echo "mkca.sh: openssl not found" >&2; exit 1; }

say() { [[ "$QUIET" == 1 ]] || echo "mkca.sh: $*"; }
changed() { echo "mkca.sh: $*"; }

PRIMARY_HOSTNAME="${HOSTNAME_ARG:-$(hostname 2>/dev/null || echo satd)}"
# A hostname that is already a FQDN must not become `host.example.com.local`.
if [[ "$PRIMARY_HOSTNAME" == *.* ]]; then
    MDNS_NAME=""
else
    MDNS_NAME="${PRIMARY_HOSTNAME}.local"
fi

# ---------------------------------------------------------------------------
# SAN set
# ---------------------------------------------------------------------------
# Order matters only in that the recorded list must be stable across runs, or
# every run would look like a SAN change and reissue. Hence the sort.
declare -a DNS_NAMES=("localhost" "$PRIMARY_HOSTNAME")
[[ -n "$MDNS_NAME" ]] && DNS_NAMES+=("$MDNS_NAME")
DNS_NAMES+=(${EXTRA_NAMES[@]+"${EXTRA_NAMES[@]}"})

declare -a IP_ADDRS=("127.0.0.1" "::1")
IP_ADDRS+=(${EXTRA_IPS[@]+"${EXTRA_IPS[@]}"})

if [[ "$DETECT_IPS" == 1 ]]; then
    # Every non-loopback address the box currently holds. `hostname -I` is
    # not used: it omits IPv6 on some configurations and is absent in a
    # minimal container.
    #
    # Container and VM bridge addresses are skipped. They are not addresses a
    # client ever connects to, and they come and go as compose projects and
    # VMs start — which, since a changed SAN set triggers a reissue, would
    # otherwise churn the certificate every time a stack overlay is enabled.
    if command -v ip >/dev/null; then
        while read -r ifname addr; do
            case "$ifname" in
                docker*|br-*|veth*|virbr*|cni*|podman*|kube*|lxcbr*) continue ;;
            esac
            [[ -n "$addr" ]] && IP_ADDRS+=("$addr")
        done < <(ip -o addr show scope global 2>/dev/null \
                    | awk '{ sub(/\/.*/, "", $4); print $2, $4 }' | sort -u)
    fi
fi

dedupe_sorted() {
    printf '%s\n' "$@" | grep -v '^$' | sort -u
}

mapfile -t DNS_NAMES < <(dedupe_sorted ${DNS_NAMES[@]+"${DNS_NAMES[@]}"})
mapfile -t IP_ADDRS < <(dedupe_sorted ${IP_ADDRS[@]+"${IP_ADDRS[@]}"})

SAN_RECORD=""
for n in ${DNS_NAMES[@]+"${DNS_NAMES[@]}"}; do SAN_RECORD+="DNS:$n"$'\n'; done
for a in ${IP_ADDRS[@]+"${IP_ADDRS[@]}"}; do SAN_RECORD+="IP:$a"$'\n'; done

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
mkdir -p "$DIR"
chmod 0750 "$DIR"
CA_KEY="$DIR/ca.key"
CA_CRT="$DIR/ca.crt"
CA_SRL="$DIR/ca.srl"
LEAF_KEY="$DIR/leaf.key"
LEAF_CRT="$DIR/leaf.crt"
FULLCHAIN="$DIR/fullchain.crt"
SANS_FILE="$DIR/leaf.sans"

apply_owner() {
    [[ -n "$OWNER" ]] || return 0
    chown "$OWNER" "$@" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# CA — created once, never rotated automatically.
# ---------------------------------------------------------------------------
if [[ ! -s "$CA_KEY" || ! -s "$CA_CRT" ]]; then
    changed "creating the local CA in $DIR"
    umask 077
    openssl ecparam -genkey -name prime256v1 -out "$CA_KEY.tmp" 2>/dev/null
    # PKCS#8 rather than SEC1: it is the form every TLS stack in the tree
    # reads without special-casing, rustls included.
    openssl pkcs8 -topk8 -nocrypt -in "$CA_KEY.tmp" -out "$CA_KEY"
    rm -f "$CA_KEY.tmp"
    openssl req -x509 -new -key "$CA_KEY" -sha256 -days "$CA_DAYS" \
        -out "$CA_CRT" \
        -subj "/CN=satd local CA ($PRIMARY_HOSTNAME)/O=satd appliance" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    # A fresh CA cannot have signed the existing leaf. Dropping the leaf here
    # is what makes `rm ca.*` a working rotation: without it the old leaf
    # would survive with an unverifiable signature.
    rm -f "$LEAF_CRT" "$FULLCHAIN" "$SANS_FILE" "$CA_SRL"
fi

# ---------------------------------------------------------------------------
# Leaf — reissued on expiry, SAN change, or --force.
# ---------------------------------------------------------------------------
need_leaf=0
reason=""
if [[ "$FORCE" == 1 ]]; then
    need_leaf=1; reason="--force"
elif [[ ! -s "$LEAF_CRT" || ! -s "$LEAF_KEY" || ! -s "$FULLCHAIN" ]]; then
    need_leaf=1; reason="no current certificate"
elif [[ ! -s "$SANS_FILE" ]] || ! diff -q <(printf '%s' "$SAN_RECORD") "$SANS_FILE" >/dev/null 2>&1; then
    need_leaf=1; reason="the name/address set changed"
elif ! openssl x509 -in "$LEAF_CRT" -noout -checkend $((RENEW_WITHIN * 86400)) >/dev/null 2>&1; then
    need_leaf=1; reason="expires within ${RENEW_WITHIN}d"
fi

if [[ "$need_leaf" == 1 ]]; then
    changed "issuing the server certificate ($reason)"
    umask 077
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    openssl ecparam -genkey -name prime256v1 -out "$tmp/leaf.sec1" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in "$tmp/leaf.sec1" -out "$tmp/leaf.key"

    {
        echo "basicConstraints=critical,CA:FALSE"
        # digitalSignature only: an ECDSA key signs, it does not encipher, and
        # listing keyEncipherment here would be a lie some verifiers act on.
        echo "keyUsage=critical,digitalSignature"
        echo "extendedKeyUsage=serverAuth"
        echo "subjectKeyIdentifier=hash"
        echo "authorityKeyIdentifier=keyid,issuer"
        printf 'subjectAltName=@alt_names\n\n[alt_names]\n'
        i=0
        for n in ${DNS_NAMES[@]+"${DNS_NAMES[@]}"}; do
            i=$((i + 1)); echo "DNS.$i=$n"
        done
        i=0
        for a in ${IP_ADDRS[@]+"${IP_ADDRS[@]}"}; do
            i=$((i + 1)); echo "IP.$i=$a"
        done
    } > "$tmp/leaf.ext"

    openssl req -new -key "$tmp/leaf.key" -out "$tmp/leaf.csr" \
        -subj "/CN=$PRIMARY_HOSTNAME" 2>/dev/null
    openssl x509 -req -in "$tmp/leaf.csr" \
        -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial -CAserial "$CA_SRL" \
        -days "$LEAF_DAYS" -sha256 -extfile "$tmp/leaf.ext" \
        -out "$tmp/leaf.crt" 2>/dev/null

    # Verify before installing. A leaf that does not chain to its own CA is
    # a silent outage on every surface at once, and it is cheap to rule out
    # here rather than discover from a client.
    openssl verify -CAfile "$CA_CRT" "$tmp/leaf.crt" >/dev/null

    # Install atomically-ish: key first, then the certs, then the SAN record.
    # The SAN record is written last on purpose — if anything above fails,
    # the next run sees a missing/stale record and reissues rather than
    # trusting a half-written state.
    mv "$tmp/leaf.key" "$LEAF_KEY"
    mv "$tmp/leaf.crt" "$LEAF_CRT"
    cat "$LEAF_CRT" "$CA_CRT" > "$FULLCHAIN"
    printf '%s' "$SAN_RECORD" > "$SANS_FILE"
    rm -rf "$tmp"
    trap - EXIT
else
    say "certificate is current; nothing to do"
fi

chmod "$KEY_MODE" "$CA_KEY" "$LEAF_KEY"
chmod 0644 "$CA_CRT" "$LEAF_CRT" "$FULLCHAIN" "$SANS_FILE"
apply_owner "$CA_KEY" "$CA_CRT" "$LEAF_KEY" "$LEAF_CRT" "$FULLCHAIN" "$SANS_FILE" "$DIR"
[[ -f "$CA_SRL" ]] && { chmod 0644 "$CA_SRL"; apply_owner "$CA_SRL"; }

if [[ "$QUIET" != 1 ]]; then
    echo "mkca.sh: CA          $CA_CRT"
    echo "mkca.sh: certificate $FULLCHAIN (key $LEAF_KEY)"
    echo "mkca.sh: valid for   $(printf '%s' "$SAN_RECORD" | tr '\n' ' ')"
    echo "mkca.sh: expires     $(openssl x509 -in "$LEAF_CRT" -noout -enddate | cut -d= -f2)"
fi
