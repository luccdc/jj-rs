{
  description = "Jiujitsu Rust";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    flake-parts.url = "github:hercules-ci/flake-parts";

    busybox = {
      url =
        "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox";
      flake = false;
    };
  };

  outputs = inputs@{ self, flake-parts, crane, rust-overlay, busybox, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ ];

      systems = [ "x86_64-linux" ];

      perSystem = { config, pkgs, lib, system, ... }:
        let
          pkgs = import self.inputs.nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
            config.allowUnfreePredicate = pkg:
              builtins.elem (lib.getName pkg) [ "vagrant" ];
          };

          devShellTools = with pkgs; [
            rust-analyzer

            # Debuggers
            gdb

            # Cargo lint tools
            taplo
            cargo-deny

            # Test runner
            cargo-nextest
            vagrant

            # Docs
            man-pages
            man-pages-posix
          ];

          busybox-gzipped = pkgs.runCommand "busybox-gzipped" { } ''
            TEMP="$(mktemp -d)"

            cp ${busybox} "$TEMP/busybox"
            ${pkgs.busybox}/bin/gzip "$TEMP/busybox"

            cp "$TEMP/busybox.gz" $out
          '';

          craneLib = (crane.mkLib pkgs).overrideToolchain (p:
            p.rust-bin.stable.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [ "x86_64-unknown-linux-musl" ];
            });

          src = craneLib.cleanCargoSource ./.;

          commonArgs = {
            inherit src;

            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            CARGO_BUILD_RUSTFLAGS = "-Ctarget-feature=+crt-static";

            BUSYBOX_GZIPPED = busybox-gzipped;
          };

          cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
            name = "jiujitsu-deps-linux";
            cargoExtraArgs = "--locked --target=x86_64-unknown-linux-musl";
          });

          jiujitsu = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;

            name = "jiujitsu";

            cargoExtraArgs = "--locked --target=x86_64-unknown-linux-musl";
          });
        in {
          _module.args.pkgs = pkgs;

          checks = {
            inherit jiujitsu;

            jj-clippy =
              craneLib.cargoClippy (commonArgs // { inherit cargoArtifacts; });

            jj-format = craneLib.cargoFmt { inherit src; };

            jj-taploFmt = craneLib.taploFmt {
              src = pkgs.lib.sources.sourceFilesBySuffices src [ ".toml" ];
            };

            jj-nextest = craneLib.cargoNextest (commonArgs // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
              cargoNextestPartitionsExtraArgs = "--no-tests=pass";
            });
          };

          packages = {
            default = jiujitsu;

            inherit jiujitsu busybox-gzipped;
          };

          devShells.default = craneLib.devShell ({
            name = "jj";

            packages = devShellTools;

            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            CARGO_BUILD_RUSTFLAGS = "-Ctarget-feature=+crt-static";

            BUSYBOX_GZIPPED = busybox-gzipped;
          });
        };
    };
}
