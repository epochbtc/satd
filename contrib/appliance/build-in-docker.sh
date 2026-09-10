#!/bin/bash
# build-in-docker.sh — run build.sh in a container that has the build tools.
#
#   contrib/appliance/build-in-docker.sh --flavor core --out out/
#
# The host needs docker and nothing else: no root, no mmdebstrap, no
# qemu-img, and no KVM. The container is privileged because building a disk
# image means creating loop devices and chrooting into the result, which
# needs real block-device access.
#
# Every argument is passed through to build.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BUILDER_IMAGE="${SATD_APPLIANCE_BUILDER:-debian:trixie}"

# --out is resolved inside the container, so the default has to be a path
# that exists in the mounted repository.
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

# `target/` is commonly a symlink to a build cache on another filesystem.
# Bind-mounting the repository alone gives the container a dangling link —
# the symlink's literal destination does not exist inside — and the build
# fails on "no target/release/satd" while the binaries sit right there on
# the host. Mount the resolved directory at a path of our own and point
# build.sh at it, rather than trying to bind over the symlink itself.
if [[ -L "$REPO/target" ]] && [[ ! " $* " == *" --satd-bin "* ]]; then
    real_target="$(readlink -f "$REPO/target")"
    if [[ -d "$real_target/release" ]]; then
        echo "build-in-docker.sh: target/ is a symlink; mounting $real_target as /satd-target"
        MOUNTS+=(-v "$real_target:/satd-target:ro")
        EXTRA_ARGS+=(--satd-bin /satd-target/release)
    fi
fi

echo "build-in-docker.sh: using $BUILDER_IMAGE"
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
    "${MOUNTS[@]}" \
    -w /repo \
    -e DEBIAN_FRONTEND=noninteractive \
    -e DEBIAN_MIRROR="${DEBIAN_MIRROR:-}" \
    "$BUILDER_IMAGE" \
    bash -c '
set -euo pipefail
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    mmdebstrap parted dosfstools e2fsprogs qemu-utils \
    ca-certificates fdisk uidmap > /dev/null
exec /repo/contrib/appliance/build.sh "$@"
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
