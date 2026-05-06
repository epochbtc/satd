# syntax=docker/dockerfile:1.7

# Multi-stage Docker build for satd.
#
# Build stage: Debian + rustup pinned to the toolchain CI uses (1.93). Cached
# Cargo registry + git via BuildKit cache mounts so iterative builds are fast.
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

ARG RUST_VERSION=1.93
ARG DEBIAN_VERSION=bookworm

FROM docker.io/library/debian:${DEBIAN_VERSION}-slim AS builder
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
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --bin satd --bin sat-cli \
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
