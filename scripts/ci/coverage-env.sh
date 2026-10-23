# Source this (bash) to run plain cargo commands under cargo-llvm-cov:
#
#   . scripts/ci/coverage-env.sh
#   cargo build -p sat-cli && cargo test --all
#   cargo llvm-cov report --html
#
# `cargo llvm-cov show-env` instruments every workspace crate, the binaries
# included, so the satd and sat-cli processes the regtest and E2E harnesses
# spawn are measured too. On its own that is not enough: the harnesses stop
# satd with Child::kill(), which is SIGKILL, and a process only writes its
# profile when it exits normally. Every spawned node's coverage was lost, and
# `satd::main` read as never run.
#
# LLVM's continuous mode fixes that: with `%c` in LLVM_PROFILE_FILE the
# counters are mapped onto the profile file and updated in place, so they
# survive SIGKILL. On Linux it needs code built with
# `-runtime-counter-relocation`. cargo-llvm-cov has no option for either, so
# this appends the flag to the flags its rustc wrapper adds to workspace
# crates. That variable is an internal interface of cargo-llvm-cov (pinned in
# coverage.yml); if it disappears this fails rather than silently measuring
# less. Continuous mode cannot share files between processes (`%m`), so each
# process writes its own (`%p`).

eval "$(cargo llvm-cov show-env --sh)"
if [ -z "${__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS:-}" ] || [ -z "${CARGO_LLVM_COV_TARGET_DIR:-}" ]; then
    echo "error: cargo llvm-cov show-env no longer sets the variables coverage-env.sh extends" >&2
    return 1 2>/dev/null || exit 1
fi
# The wrapper's flags are separated by 0x1f, as cargo's CARGO_ENCODED_RUSTFLAGS.
export __CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS="${__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS}"$'\x1f'"-Cllvm-args=-runtime-counter-relocation"
export LLVM_PROFILE_FILE="$CARGO_LLVM_COV_TARGET_DIR/satd-cov-%p%c.profraw"
