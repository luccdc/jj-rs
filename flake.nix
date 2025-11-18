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

    libpcap-src = {
      url = "git+https://github.com/the-tcpdump-group/libpcap";
      flake = false;
    };
  };

  outputs = inputs@{ self, flake-parts, crane, rust-overlay, libpcap-src, ... }:
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

          libpcap-static = pkgs.stdenv.mkDerivation {
            name = "libpcap-static";

            buildInputs = with pkgs; [ clang automake bison cmake flex musl ];

            src = libpcap-src;

            configurePhase = ''
              cmake \
                  -DCMAKE_BUILD_TYPE=MinSizeRel \
                  -DBUILD_SHARED_LIBS=OFF \
                  -DDISABLE_BLUETOOTH=ON \
                  -DDISABLE_DAG=ON \
                  -DDISABLE_DBUS=ON \
                  -DDISABLE_DPDK=ON \
                  -DDISABLE_NETMAP=ON \
                  -DDISABLE_RDMA=ON \
                  -DDISABLE_LINUX_USBMON=ON \
                  -DDISABLE_SNF=ON \
                  -DPCAP_TYPE=linux \
                  .
            '';

            buildPhase = ''
              cmake --build . --target pcap_static
            '';

            installPhase = ''
              mkdir -p $out/lib

              cp libpcap.a $out/lib
            '';
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

          libraries = [ libpcap-static ];

          gzip-binary = name: binary:
            pkgs.runCommand "${name}-gzipped" { } ''
              TEMP="$(mktemp -d)"

              cp ${binary} "$TEMP/${name}"
              ${pkgs.busybox}/bin/gzip "$TEMP/${name}"

              cp "$TEMP/${name}.gz" $out
            '';

          busybox-gzipped =
            gzip-binary "busybox" "${pkgsStatic.busybox}/bin/busybox";
          jq-gzipped = gzip-binary "jq" "${pkgsStatic.jq.bin}/bin/jq";
          nft-gzipped = gzip-binary "nft"
            ("${pkgsStatic.nftables.override { withCli = false; }}/bin/nft");
          tmux-gzipped = gzip-binary "tmux" "${pkgsStatic.tmux}/bin/tmux";
          tcpdump-gzipped =
            gzip-binary "tcpdump" "${pkgsStatic.tcpdump}/bin/tcpdump";
          zsh-gzipped = gzip-binary "zsh" "${pkgsStatic.zsh}/bin/zsh";

          craneLib = (crane.mkLib pkgs).overrideToolchain (p:
            p.rust-bin.nightly.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [ "x86_64-unknown-linux-musl" ];
            });

          src = ./.;

          commonArgs = {
            inherit src;

            buildInputs = libraries;
            nativeBuildInputs = libraries;

            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            CARGO_BUILD_RUSTFLAGS = "-Ctarget-feature=+crt-static";

            BUSYBOX_GZIPPED = busybox-gzipped;
            JQ_GZIPPED = jq-gzipped;
            NFT_GZIPPED = nft-gzipped;
            TMUX_GZIPPED = tmux-gzipped;
            TCPDUMP_GZIPPED = tcpdump-gzipped;
            ZSH_GZIPPED = zsh-gzipped;
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

            packages = devShellTools ++ libraries;

            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            CARGO_BUILD_RUSTFLAGS = "-Ctarget-feature=+crt-static";

            BUSYBOX_GZIPPED = busybox-gzipped;
            JQ_GZIPPED = jq-gzipped;
            NFT_GZIPPED = nft-gzipped;
            TMUX_GZIPPED = tmux-gzipped;
            TCPDUMP_GZIPPED = tcpdump-gzipped;
            ZSH_GZIPPED = zsh-gzipped;
          });
        };
    };
}
