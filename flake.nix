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
    jq = {
      url =
        "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-amd64";
      flake = false;
    };
  };

  outputs = inputs@{ self, flake-parts, crane, rust-overlay, busybox, jq, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ ];

      systems = [ "x86_64-linux" ];

      perSystem = { config, lib, system, ... }:
        let
          pkgs = import self.inputs.nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
            config.allowUnfreePredicate = pkg:
              builtins.elem (lib.getName pkg) [ "vagrant" ];
          };

          pkgsStatic = pkgs.pkgsStatic;

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

            cargo-expand
          ];

          gzip-binary = name: binary:
            pkgs.runCommand "${name}-gzipped" { } ''
              TEMP="$(mktemp -d)"

              cp ${binary} "$TEMP/${name}"
              ${pkgs.busybox}/bin/gzip "$TEMP/${name}"

              cp "$TEMP/${name}.gz" $out
            '';

          busybox-gzipped = gzip-binary "busybox" busybox;
          jq-gzipped = gzip-binary "jq" jq;
          nft-gzipped = gzip-binary "nft"
            ("${pkgsStatic.nftables.override { withCli = false; }}/bin/nft");
          tmux-gzipped = gzip-binary "tmux" "${pkgsStatic.tmux}/bin/tmux";
          tcpdump-gzipped =
            gzip-binary "tcpdump" "${pkgsStatic.tcpdump}/bin/tcpdump";

          craneLib = (crane.mkLib pkgs).overrideToolchain (p:
            p.rust-bin.nightly.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [ "x86_64-unknown-linux-musl" ];
            });

          src = ./.;

          commonArgs = {
            inherit src;

            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            CARGO_BUILD_RUSTFLAGS = "-Ctarget-feature=+crt-static";

            BUSYBOX_GZIPPED = busybox-gzipped;
            JQ_GZIPPED = jq-gzipped;
            NFT_GZIPPED = nft-gzipped;
            TMUX_GZIPPED = tmux-gzipped;
            TCPDUMP_GZIPPED = tcpdump-gzipped;
          };

          cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
            name = "jiujitsu-deps-linux";
            cargoExtraArgs = "--locked --target=x86_64-unknown-linux-musl";
          });

          jiujitsu = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;

            name = "jiujitsu";

            cargoExtraArgs = "--locked --target=x86_64-unknown-linux-musl";
            cargoTestExtraArgs = "--all";
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
            JQ_GZIPPED = jq-gzipped;
            NFT_GZIPPED = nft-gzipped;
            TMUX_GZIPPED = tmux-gzipped;
            TCPDUMP_GZIPPED = tcpdump-gzipped;
          });
        };
    };
}
