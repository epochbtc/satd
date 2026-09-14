# The SDK ships the whole build: `make` packs the .s9pk, `make install`
# sideloads it to the server in ~/.startos/config.yaml. Overrides go above the
# include.

# The image publishes linux/amd64 and linux/arm64 only (see the manifest's
# `arch`). The SDK's default also packs riscv, which the registry's build
# matrix would then attempt and fail on.
ARCHES := x86 arm

include node_modules/@start9labs/start-sdk/s9pk.mk
