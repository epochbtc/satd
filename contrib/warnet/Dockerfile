# Warnet lab image: satd laid out like the `bitcoindevproject/bitcoin` image,
# so Warnet's stock `bitcoincore` Helm chart runs it unchanged.
#
# The chart has no command/args/env override for its main container and
# assumes Bitcoin Core's layout:
#   - the liveness probe is `pidof bitcoind`       -> bitcoind is a symlink to satd
#   - `warnet bitcoin rpc` execs `bitcoin-cli`     -> a sat-cli adapter (see bitcoin-cli)
#   - bitcoin.conf is mounted at /root/.bitcoin    -> datadir /root/.bitcoin, run as root
#   - the container starts with no arguments       -> entrypoint.sh supplies -datadir
#
# This is a test-network image, not an operator image. Run the published
# ghcr.io/epochbtc/satd for anything else.
#
# Warnet only renders image tags of the form X.Y[.Z][-suffix]; tag builds of
# this image `<satd version>-warnet<N>` (for example 0.6.0-warnet0).
ARG SATD_IMAGE=ghcr.io/epochbtc/satd:latest
FROM ${SATD_IMAGE}

USER root
COPY entrypoint.sh /entrypoint.sh
COPY bitcoin-cli /usr/local/bin/bitcoin-cli
RUN ln -s /usr/local/bin/satd /usr/local/bin/bitcoind \
    && chmod 0755 /entrypoint.sh /usr/local/bin/bitcoin-cli \
    && mkdir -p /root/.bitcoin

ENV BITCOIN_DATA=/root/.bitcoin
# The inherited HEALTHCHECK probes the RPC port; Warnet networks are regtest.
ENV SATD_RPCPORT=18443
WORKDIR /root/.bitcoin
EXPOSE 18443 18444
ENTRYPOINT ["/entrypoint.sh"]
CMD []
