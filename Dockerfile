# syntax=docker/dockerfile:1.7

# Multi-stage Docker build for satd, with a cargo-chef dependency-caching layer.
#
#   chef    — base toolchain + system build deps + the cargo-chef binary.
#             Rebuilt only when the toolchain or system deps change.
#   planner — distils the workspace into a `recipe.json` (the dependency graph,
#             independent of first-party source contents).
#   builder — `cargo chef cook` compiles ONLY the dependency graph from the
#             recipe, then `COPY . .` + `cargo build` compiles first-party
#             crates on top. Because cook's inputs are just recipe.json (not the
#             source tree), its layer — which holds the expensive native builds
#             (rocksdb, secp256k1, …) — stays cache-hit across ordinary code
#             changes. Only Cargo.lock changes bust it.
#
# TWO non-obvious requirements make cargo-chef actually reuse the cooked deps
# instead of silently recompiling the whole graph in the final stage:
#
#  1. Identical toolchain in cook and the final build. cargo's `-Cmetadata`
#     hash embeds the exact rustc version, and cargo-chef's cook skeleton does
#     NOT include rust-toolchain.toml — so cook would use rustup's *default*
#     toolchain while `COPY . .` gives the final build the *pinned* one. If
#     those differ by even a patch release, every dependency's hash misses and
#     the cooked artifacts are wasted. We pin RUST_VERSION to the exact channel
#     in rust-toolchain.toml AND copy that file into the shared base stage, so
#     every stage compiles with the same rustc.
#  2. Identical cargo flags in cook and the final build (same --bin selection,
#     profile). Different feature unification = different fingerprints.
#
# No `--mount=type=cache` is used in cook/build: cargo-chef's incrementality
# comes from Docker *layer* caching (which the CI GHA backend persists), and
# that requires the cooked artifacts to live in the real layer filesystem.
#
# Runtime stage: debian:bookworm-slim. Distroless was considered but rejected —
# operators routinely `docker exec -it` to inspect a running node, and a base
# without busybox/coreutils makes that debugging story worse than the size win
# is worth. The runtime layer is ~80 MB before the binaries.
#
# Build:
#   docker build -t satd:dev .
#
# Run (mainnet, persistent volume):
#   docker run --rm -v satd-data:/var/lib/satd -p 8333:8333 satd:dev
#
# Run with cookie auth + metrics:
#   docker run --rm \
#     -v satd-data:/var/lib/satd \
#     -p 8333:8333 -p 127.0.0.1:8332:8332 -p 127.0.0.1:9332:9332 \
#     satd:dev --rpcbind=0.0.0.0 --rpcallowip=0.0.0.0/0 \
#              --metricsport=9332 --metricsbind=0.0.0.0
#
# CLI against the running container:
#   docker exec satd sat-cli getblockchaininfo

# RUST_VERSION MUST match rust-toolchain.toml's `channel` exactly (not a
# floating `1.93`, which resolves to the latest patch and diverges from the
# pin — that divergence is what breaks cargo-chef's dependency cache).
ARG RUST_VERSION=1.93.0
ARG DEBIAN_VERSION=bookworm

FROM docker.io/library/debian:${DEBIAN_VERSION}-slim AS chef
ARG RUST_VERSION

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH

# Build deps:
#   - clang + libclang-dev: rocksdb-sys bindgen
#   - cmake + make + g++ + pkg-config: rocksdb / zstd / lz4 native code
#   - libssl-dev: reqwest's default TLS backend is `native-tls`, which
#     pulls openssl-sys on Linux. We deliberately don't switch the
#     workspace to rustls-only: that requires auditing every transitive
#     dependency (and any indirect openssl-sys pull-in is silent). The
#     openssl path is battle-tested and the apt package is a known
#     quantity, so we accept the larger system dependency rather than
#     shoulder the rustls audit burden.
#   - ca-certificates: rustup downloads
#   - curl: rustup installer
#   - git: build.rs scripts that read git metadata
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        libclang-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION}

WORKDIR /src

# Pin the toolchain for EVERY build stage (see header note #1). Copying
# rust-toolchain.toml into the base stage means cook — which otherwise builds
# from a skeleton without it — uses the same rustc as the final build. The
# subsequent cargo invocation materialises the pinned toolchain + components
# into this cached layer.
COPY rust-toolchain.toml .

# cargo-chef binary. Pinned to the 0.1 line; lives in this base stage so it is
# compiled once and reused by both the planner and builder stages (and cached
# until the toolchain/deps change). Bump deliberately, not by drift.
RUN cargo install cargo-chef --locked --version "^0.1"


# Distil the workspace into a dependency recipe. Only Cargo.toml/Cargo.lock
# content (and member layout) feed the recipe, so this stage's *output*
# changes only when dependencies change — which is what makes the cook layer
# below survive ordinary source edits.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json


FROM chef AS builder

# Cook the dependency graph only. This is the expensive layer (rocksdb &
# friends) and it is keyed on recipe.json alone — a source-only change leaves
# it cache-hit.
#
# events/build.rs compiles the gRPC protobufs (satd enables `events/grpc`) and
# reads events/proto/** at build time. cargo-chef's skeleton reconstructs
# Cargo.toml + build.rs but NOT arbitrary data files, so the proto tree must be
# present before cook or the build script fails. It changes rarely, so copying
# it here doesn't meaningfully erode the cook cache.
#
# The cook flags MUST match the final `cargo build` exactly (see header note
# #2).
COPY --from=planner /src/recipe.json recipe.json
COPY events/proto events/proto
RUN cargo chef cook --release --locked --bin satd --bin sat-cli --recipe-path recipe.json

# Compile first-party crates on top of the cooked dependency artifacts already
# sitting in target/.
COPY . .
RUN cargo build --release --locked --bin satd --bin sat-cli \
    && install -Dm755 target/release/satd /out/satd \
    && install -Dm755 target/release/sat-cli /out/sat-cli


FROM docker.io/library/debian:${DEBIAN_VERSION}-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Runtime deps:
#   - libssl3: reqwest's openssl backend (matches the build stage)
#   - ca-certificates: outbound HTTPS for fee oracles, webhooks, etc.
#   - tini: PID 1 signal forwarding so SIGTERM reaches satd cleanly
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user. UID/GID 2121 (Core's docker images use 1000;
# we deliberately pick a fixed non-1000 to avoid clashing with the host
# user when the datadir is bind-mounted from $HOME).
ARG SATD_UID=2121
ARG SATD_GID=2121
RUN groupadd --system --gid ${SATD_GID} satd \
    && useradd --system --uid ${SATD_UID} --gid satd \
        --home-dir /var/lib/satd --shell /usr/sbin/nologin satd \
    && install -d -o satd -g satd -m 0750 /var/lib/satd

COPY --from=builder /out/satd /usr/local/bin/satd
COPY --from=builder /out/sat-cli /usr/local/bin/sat-cli

USER satd
WORKDIR /var/lib/satd
VOLUME ["/var/lib/satd"]

# Mainnet ports. Other networks (testnet/signet/regtest) need their own
# `-p` mappings; we don't expose them by default to avoid surprising
# operators who run a single network at a time.
EXPOSE 8332 8333

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/satd"]
CMD ["--datadir=/var/lib/satd"]
