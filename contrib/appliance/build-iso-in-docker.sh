#!/bin/bash
# build-iso-in-docker.sh — run build-iso.sh in a container with the tools.
# The host needs docker and nothing else. See build-in-docker.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BUILDER_IMAGE="${SATD_APPLIANCE_BUILDER:-debian:trixie}"

MOUNTS=(-v "$REPO:/repo")
EXTRA_ARGS=()

# --out is a host path the caller expects to find the artifacts in, but the
# container only sees what is mounted. Without this the build succeeds, the
# image is written inside the container, and it disappears when the
# container exits — a silent success that produces nothing.
out_dir=""
prev=""
for arg in "$@"; do
    [[ "$prev" == "--out" ]] && out_dir="$arg"
    prev="$arg"
done
if [[ -n "$out_dir" ]]; then
    mkdir -p "$out_dir"
    out_dir="$(readlink -f "$out_dir")"
    # Mounted at its own absolute path, unconditionally — including when it
    # lies inside the repository. A path under $REPO is visible in the
    # container as /repo/..., NOT at the host's absolute path, so skipping
    # the mount for those would have the build create the directory inside
    # the container, write several GB into it, and lose all of it on exit
    # while reporting success. Nested bind mounts are fine.
    echo "$(basename "$0"): mounting output directory $out_dir"
    MOUNTS+=(-v "$out_dir:$out_dir")
fi
if [[ -L "$REPO/target" ]] && [[ ! " $* " == *" --satd-bin "* ]]; then
    real_target="$(readlink -f "$REPO/target")"
    if [[ -d "$real_target/release" ]]; then
        MOUNTS+=(-v "$real_target:/satd-target:ro")
        EXTRA_ARGS+=(--satd-bin /satd-target/release)
    fi
fi

# `exec` is deliberately not used: the point of the check after this is to
# still be here when the container exits.
#
# The arguments are passed in explicitly (`run_build "$@"` below). Inside a
# function `"$@"` is the FUNCTION's arguments, so wrapping the invocation
# without forwarding them silently drops every flag the caller gave —
# `--flavor desktop` included, which then builds a core image into the
# directory you asked the desktop one to go to.
run_build() {
docker run --rm --privileged \
    "${MOUNTS[@]}" -w /repo \
    -e DEBIAN_FRONTEND=noninteractive \
    "$BUILDER_IMAGE" \
    bash -c '
set -euo pipefail
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    mmdebstrap parted dosfstools e2fsprogs qemu-utils \
    squashfs-tools xorriso grub-pc-bin grub-efi-amd64-bin grub-common mtools \
    ca-certificates fdisk > /dev/null
exec /repo/contrib/appliance/build-iso.sh "$@"
' -- "$@" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
}

run_build "$@"
status=$?

if [[ $status -eq 0 && -n "$out_dir" ]]; then
    # The failure this catches is a silent one: the build reports success
    # having written its artifacts to a path that existed only inside the
    # container.
    shopt -s nullglob
    produced=( "$out_dir"/* )
    shopt -u nullglob
    if [[ ${#produced[@]} -eq 0 ]]; then
        echo "$(basename "$0"): the build reported success but $out_dir is empty." >&2
        echo "$(basename "$0"): the output directory was not visible inside the container." >&2
        exit 1
    fi
fi
exit $status
