{
  # satd reproducible build via Nix.
  #
  # See `docs/PACKAGING.md` §"Reproducible build via Nix" for the
  # operator-facing story. This file is the source for two outputs:
  #
  #   - `nix build` produces deterministic `satd` and `sat-cli` binaries
  #     under `result/bin/`. Two builds from the same commit on two
  #     hosts produce the same SHA256.
  #
  #   - `nix develop` drops into a shell with the workspace's full
  #     native toolchain (clang, libclang, cmake, openssl, plus the
  #     pinned rust). Useful for contributors who don't want to manage
  #     rustup themselves.
  #
  # Toolchain pin lives in `rust-toolchain.toml` at the repo root and
  # is the single source of truth (also read by rustup).
  #
  # v1 scope (this PR): x86_64-linux + aarch64-linux. Nix-to-Nix
  # repro only — matching the rustup-stable tarball binary is a
  # separate exercise (linker / build-id alignment) deferred to v1.x.

  description = "satd — Bitcoin Core-compatible full node in Rust (reproducible build)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane = {
      url = "github:ipetkov/crane";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self
    , nixpkgs
    , rust-overlay
    , crane
    , flake-utils
    }:
    flake-utils.lib.eachSystem
      [
        flake-utils.lib.system.x86_64-linux
        flake-utils.lib.system.aarch64-linux
      ]
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          # Read the channel + components from rust-toolchain.toml so
          # the flake and `cargo` agree on what rustc to use.
          rustToolchain =
            pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          # crane's `cleanCargoSource` strips non-Rust files. The
          # workspace has `events/proto/*.proto` files that
          # `tonic_build` reads at compile time; keep those.
          # Also keep license/attribution files referenced by some
          # downstream build scripts and the `vendor/` directories.
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            name = "satd-source";
            filter = path: type:
              let
                rel = pkgs.lib.removePrefix (toString ./. + "/") (toString path);
                isProto = pkgs.lib.hasSuffix ".proto" rel;
                isVendorAttribution =
                  pkgs.lib.hasInfix "/vendor/" ("/" + rel);
                isCargoOrRust = craneLib.filterCargoSources path type;
              in
              isProto || isVendorAttribution || isCargoOrRust;
          };

          # Native deps every cargo build in this workspace needs.
          # Mirrors the apt list in `Dockerfile` and the
          # `Install Linux build deps` step in
          # `.github/workflows/release.yml`. Anything added there must
          # be added here.
          nativeBuildInputs = with pkgs; [
            pkg-config
            cmake
            clang
            llvmPackages.libclang.lib
          ];

          buildInputs = with pkgs; [
            openssl
            zlib
          ];

          # Env that any cargo invocation in this workspace needs to
          # find the right native deps. Set in both the build
          # derivation and `nix develop`.
          shellEnv = {
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          };

          # Additional env applied only to the build derivation. These
          # are the determinism knobs; we deliberately don't put them
          # in the dev shell because a developer running local
          # `cargo build --release` shouldn't lose debug symbols /
          # build-id by accident.
          #
          #   - ROCKSDB_DISABLE_AVX2 / PORTABLE  RocksDB's vendored
          #                     build defaults to `-march=native`
          #                     when PORTABLE is unset; that breaks
          #                     repro across runners with different
          #                     ISA caps. The release-workflow
          #                     tarball already does not use
          #                     -march=native (default rustup-stable
          #                     produces generic x86_64-v1), so this
          #                     matches that behaviour.
          #
          #   - SOURCE_DATE_EPOCH   pinned to the flake's
          #                     `lastModifiedDate` so any build
          #                     script that bakes a timestamp gets a
          #                     stable one. cc-rs and tonic-build
          #                     respect it.
          #
          #   - CARGO_PROFILE_RELEASE_STRIP / RUSTFLAGS  drop debug
          #                     symbols + linker build-id for a
          #                     deterministic ELF.
          buildEnv = shellEnv // {
            ROCKSDB_DISABLE_AVX2 = "1";
            PORTABLE = "1";
            SOURCE_DATE_EPOCH = toString (self.lastModifiedDate or 1);
            CARGO_PROFILE_RELEASE_STRIP = "symbols";
            RUSTFLAGS = "-C link-arg=-Wl,--build-id=none";
          };

          commonArgs = buildEnv // {
            inherit src nativeBuildInputs buildInputs;
            strictDeps = true;
            # `--locked` mirrors the release workflow; deps must
            # match Cargo.lock exactly. No registry fetches at
            # build time.
            cargoExtraArgs = "--locked";
            # The workspace's package version (read from the
            # workspace.package table) is a placeholder until a real
            # release. crane wants a name+version anyway; using the
            # workspace pin keeps the derivation name predictable.
            pname = "satd-workspace";
            version = "0.1.0";
          };

          # First-pass build: produce the dep-only artifacts. Cached
          # in the nix store keyed by Cargo.lock contents, so source
          # edits don't re-build the dep graph.
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          # Second-pass: workspace build of the binary crates we ship.
          satd = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            pname = "satd";
            # Build only the two binaries we ship as releases. The
            # workspace has additional bins (sat-tui) that operators
            # can opt into; keeping the default flake build small
            # matches the release tarball.
            cargoExtraArgs = "--locked --bin satd --bin sat-cli";
            # The default `doCheck = true` would run `cargo test`
            # inside the build derivation. We expose tests as a
            # `checks.cargo-test` derivation instead, so a packager
            # who just wants binaries doesn't pay the test cost.
            doCheck = false;
            meta = with pkgs.lib; {
              description = "Bitcoin Core-compatible full node in Rust";
              homepage = "https://github.com/epochbtc/satd";
              license = licenses.mit;
              mainProgram = "satd";
              platforms = [ "x86_64-linux" "aarch64-linux" ];
            };
          });
        in
        {
          packages = {
            inherit satd;
            default = satd;
          };

          apps = {
            satd = flake-utils.lib.mkApp {
              drv = satd;
              name = "satd";
            };
            sat-cli = flake-utils.lib.mkApp {
              drv = satd;
              name = "sat-cli";
            };
            default = flake-utils.lib.mkApp {
              drv = satd;
              name = "satd";
            };
          };

          devShells.default = pkgs.mkShell (shellEnv // {
            inputsFrom = [ satd ];
            packages = [
              rustToolchain
              pkgs.cargo-watch
              pkgs.cargo-nextest
            ];
            shellHook = ''
              echo "satd dev shell — toolchain: $(rustc --version)"
              echo "  LIBCLANG_PATH=${pkgs.llvmPackages.libclang.lib}/lib"
            '';
          });

          checks = {
            # Each check is a separate derivation so `nix flake check`
            # exposes them independently and CI can address them
            # one-by-one.
            cargo-clippy = craneLib.cargoClippy (commonArgs // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets --all-features -- -D warnings";
            });

            cargo-fmt = craneLib.cargoFmt {
              inherit src;
              # rustfmt isn't gated on `--all-features` so this is a
              # cheap parallel check.
            };

            cargo-test = craneLib.cargoTest (commonArgs // {
              inherit cargoArtifacts;
              cargoTestExtraArgs = "--workspace --all-features";
            });
          };

          formatter = pkgs.nixpkgs-fmt;
        });
}
