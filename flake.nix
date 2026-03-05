{
  description = "Jiujitsu Rust";

  nixConfig = {
    extra-substituters = [ "https://judah-sotomayor.cachix.org" ];
    extra-trusted-public-keys = [
      "judah-sotomayor.cachix.org-1:I9crtW1ZCPXiklcGAbK/31DQ7T8tSHvQ3Akxx3Brzbc="
    ];
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs@{ self, nixpkgs, flake-parts, crane, rust-overlay, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ ];

      systems = [ "x86_64-linux" ];

      perSystem = { config, lib, system, ... }:
        let
          pkgs = import self.inputs.nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
            config = {
              allowUnfreePredicate = pkg:
                builtins.elem (lib.getName pkg) [ "vagrant" ];
            };
          };

          # Cross compilation requires using a different nixpkgs, and setting up
          # another craneLib
          winPkgs = import self.inputs.nixpkgs {
            overlays = [ (import rust-overlay) ];
            localSystem = system;
            crossSystem = {
              config = "x86_64-w64-mingw32";
              libc = "msvcrt";
            };
          };

          winpthreads = let
            pthreads = pkgs.pkgsCross.mingwW64.windows.pthreads.overrideAttrs
              (final: prev: { dontDisableStatic = true; });
          in pkgs.runCommand "winpthreads-static-only" { } ''
            mkdir $out
            cp -a ${pthreads}/* $out
            chmod -R +w $out
            rm $out/lib/libwinpthread.dll.a
            rm $out/lib/libpthread.dll.a
            rm $out/bin/libwinpthread-1.dll
          '';

          system-pkgs = import ./system-pkgs.nix {
            inherit nixpkgs pkgs winPkgs winpthreads;
          };

          pamtester-gzipped = pkgs.runCommand "pamtester-gzipped" { } ''
            TEMP="$(mktemp -d)"

            cd $TEMP
            ${pkgs.binutils}/bin/ar x ${
              pkgs.fetchurl {
                url =
                  "http://ftp.de.debian.org/debian/pool/main/p/pamtester/pamtester_0.1.2-4_amd64.deb";
                hash = "sha256-QzC/6TqIlYVrx/PUVj7XkGD4crmbOIZzZhFXYAFQKCU=";
              }
            }
            tar xvJpf data.tar.xz
            ${pkgs.busybox}/bin/gzip usr/bin/pamtester
            cp usr/bin/pamtester.gz $out
          '';

          pkgsStatic = pkgs.pkgsStatic;

          linuxLibraries = [
            system-pkgs.libpcap-linux-static
            system-pkgs.libmodsecurity-linux-static
            system-pkgs.libcurl-linux-static
            pkgsStatic.pcre
            pkgsStatic.libxml2
            pkgsStatic.aws-lc
            pkgsStatic.yajl
            pkgsStatic.libpsl
            pkgsStatic.zlib
            pkgsStatic.libidn2
            pkgsStatic.libunistring
            pkgsStatic.libcxx
            pkgs.mold
          ];

          windowsLibraries = (with pkgs.pkgsCross.mingwW64; [
            buildPackages.gcc
            buildPackages.clang
            winpthreads
          ]) ++ (with system-pkgs; [
            aws-lc-windows-static
            libcurl-windows-static
            libiconv-windows-static
            libidn2-windows-static
            libunistring-windows-static
            libpoco-windows-static
            libpsl-windows-static
            libpcre-windows-static
            libmodsecurity-windows-static
            libxml2-windows-static
            libmcfgthread-windows-static
          ]);

          wslDevShellTools = with pkgs; [
            rust-analyzer

            # Debuggers
            gdb

            # Cargo lint tools
            taplo
            cargo-deny

            # Test runner
            cargo-nextest

            # Docs
            man-pages
            man-pages-posix

            cargo-expand
            mold
          ];

          winDevShellTools = with pkgs;
            [ wineWow64Packages.minimal ] ++ windowsLibraries;

          devShellTools = wslDevShellTools
            ++ (with pkgs; [ vagrant shellcheck ]);

          gzip-binary = name: binary:
            pkgs.runCommand "${name}-gzipped" { } ''
              TEMP="$(mktemp -d)"

              cp ${binary} "$TEMP/${name}"
              ${pkgs.busybox}/bin/gzip "$TEMP/${name}"

              cp "$TEMP/${name}.gz" $out
            '';

          busybox-gzipped =
            gzip-binary "busybox" "${pkgsStatic.busybox}/bin/busybox";
          nft-gzipped = gzip-binary "nft"
            ("${pkgsStatic.nftables.override { withCli = false; }}/bin/nft");
          zsh-gzipped = gzip-binary "zsh" "${pkgsStatic.zsh}/bin/zsh";

          craneLib = (crane.mkLib pkgs).overrideToolchain (p:
            p.rust-bin.nightly.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [ "x86_64-unknown-linux-musl" ];
            });

          winCraneLib = (crane.mkLib winPkgs).overrideToolchain (p:
            p.rust-bin.nightly.latest.default.override {
              targets = [ "x86_64-pc-windows-gnu" ];
            });

          core-ruleset = pkgs.fetchFromGitHub {
            owner = "coreruleset";
            repo = "coreruleset";
            rev = "v4.24.0";
            hash = "sha256-BUkeQPXjS5t+UQEBjj2p0SC89q38xDLOcnsSshcgdFg=";
          };

          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              (craneLib.fileset.commonCargoSources ./.)
              ./src/commands/elk
            ];
          };

          commonArgs = rec {
            inherit src;

            CARGO_BUILD_RUSTFLAGS =
              "-Ctarget-feature=+crt-static --cfg tracing_unstable";

            CORE_RULESET = core-ruleset;
            MODSECURITY = system-pkgs.libmodsecurity-linux-static;
            LIBCLANG_PATH = pkgs.libclang.lib;

            BUSYBOX_GZIPPED = busybox-gzipped;
            NFT_GZIPPED = nft-gzipped;
            ZSH_GZIPPED = zsh-gzipped;
            PAMTESTER_GZIPPED = pamtester-gzipped;
          };

          linuxCommonArgs = commonArgs // {
            buildInputs = linuxLibraries;
            nativeBuildInputs = linuxLibraries;

            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            LIBCURL_PATH = system-pkgs.libcurl-linux-static;
            LIBC_PATH = pkgs.musl.dev;

            cargoExtraArgs = "--locked --target=x86_64-unknown-linux-musl";
          };

          windowsCommonArgs = commonArgs // {
            buildInputs = windowsLibraries;
            nativeBuildInputs = windowsLibraries;
            packages = windowsLibraries;

            CARGO_BUILD_TARGET = "x86_64-pc-windows-gnu";
            LIBCURL_PATH = system-pkgs.libcurl-windows-static;
            LIBC_PATH = pkgs.pkgsCross.mingwW64.windows.mingw_w64_headers;

            cargoExtraArgs = "--locked --target=x86_64-pc-windows-gnu";
          };

          linuxCargoArtifacts = craneLib.buildDepsOnly
            (linuxCommonArgs // { name = "jiujitsu-deps-linux"; });

          windowsCargoArtifacts = winCraneLib.buildDepsOnly (windowsCommonArgs
            // {
              name = "jiujitsu-deps-windows";
              doCheck = false;
            });

          jiujitsu-linux = craneLib.buildPackage (linuxCommonArgs // {
            cargoArtifacts = linuxCargoArtifacts;

            name = "jiujitsu-linux";
            cargoTestExtraArgs = "--all";

            strictDeps = true;
          });

          jiujitsu-windows = winCraneLib.buildPackage (windowsCommonArgs // {
            cargoArtifacts = windowsCargoArtifacts;

            name = "jiujitsu-windows";
            cargoTestExtraArgs = "--all";

            doCheck = false;
          });

          jiujitsu = pkgs.runCommand "jiujitsu" { } ''
            mkdir -p $out/bin

            cp ${jiujitsu-linux}/bin/jj-rs $out/bin/jj
            cp ${jiujitsu-windows}/bin/jj-rs.exe $out/bin/jj.exe
            cp ${tools-tarball}/jj.tgz $out/jj.tgz
          '';

          install-script-src = builtins.readFile ./install.sh;
          install-script = pkgs.writeScriptBin "install.sh" install-script-src;

          staticTools = with pkgsStatic; [ jq tcpdump tmux nftables ];

          tools-tarball = pkgs.runCommand "tools-tarball" { } ''
            mkdir -p $out
            tar -czvf $out/jj.tgz --mode=755      \
              -C ${install-script}/bin install.sh \
              -C ${jiujitsu-linux} bin            \
              ${
                lib.concatMapStringsSep ''
                  \
                '' (p: "-C ${p} bin ") staticTools
              }  \
              --transform='s,jj-rs,jj,'        \
              --transform='s,^bin,jj-bin,'        \
              --show-transformed-names            \
              --owner=0 --group=0
          '';

        in {
          _module.args.pkgs = pkgs;

          checks = {
            inherit jiujitsu-linux jiujitsu-windows;

            jj-clippy = craneLib.cargoClippy
              (linuxCommonArgs // { cargoArtifacts = linuxCargoArtifacts; });

            jj-format = craneLib.cargoFmt { inherit src; };

            jj-taploFmt = craneLib.taploFmt {
              src = pkgs.lib.sources.sourceFilesBySuffices src [ ".toml" ];
            };

            jj-nextest = craneLib.cargoNextest (linuxCommonArgs // {
              cargoArtifacts = linuxCargoArtifacts;
              partitions = 1;
              partitionType = "count";
              cargoNextestPartitionsExtraArgs = "--no-tests=pass";
            });

            shellcheck = pkgs.runCommandNoCC "shellcheck" {
              src = ./.;
              nativeBuildInputs = with pkgs; [ shellcheck ];
            } ''
              touch $out
              shellcheck --rcfile $src/.shellcheckrc \
                  $(find $src -name '*.sh') >&2
            '';
          };

          packages = {
            default = jiujitsu;

            inherit jiujitsu jiujitsu-linux jiujitsu-windows tools-tarball;

            libpoco-windows-static = system-pkgs.libpoco-windows-static;
          };

          devShells = {
            default = craneLib.devShell (rec {
              name = "jj";

              packages = devShellTools ++ linuxLibraries ++ staticTools;

              CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
              CARGO_BUILD_RUSTFLAGS =
                "-Ctarget-feature=+crt-static --cfg tracing_unstable";

              MODSECURITY = system-pkgs.libmodsecurity-linux-static;
              CORE_RULESET = core-ruleset;
              LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
              LIBCURL_PATH = "${system-pkgs.libcurl-linux-static}";
              LIBC_PATH = pkgs.musl.dev;

              BUSYBOX_GZIPPED = busybox-gzipped;
              NFT_GZIPPED = nft-gzipped;
              ZSH_GZIPPED = zsh-gzipped;
              PAMTESTER_GZIPPED = pamtester-gzipped;
            });

            windows = winCraneLib.devShell (rec {
              name = "jj";

              packages = wslDevShellTools ++ winDevShellTools;
              nativeBuildInputs = windowsLibraries;
              buildInputs = windowsLibraries;

              CARGO_BUILD_TARGET = "x86_64-pc-windows-gnu";
              CARGO_BUILD_RUSTFLAGS =
                "-Ctarget-feature=+crt-static --cfg tracing_unstable";

              MODSECURITY = system-pkgs.libmodsecurity-linux-static;
              CORE_RULESET = core-ruleset;
              LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
              LIBCURL_PATH = "${system-pkgs.libcurl-windows-static}";
              LIBC_PATH = pkgs.pkgsCross.mingwW64.windows.mingw_w64_headers;

              BUSYBOX_GZIPPED = busybox-gzipped;
              NFT_GZIPPED = nft-gzipped;
              ZSH_GZIPPED = zsh-gzipped;
              PAMTESTER_GZIPPED = pamtester-gzipped;
            });

            wsl = craneLib.devShell (rec {
              name = "jj";

              packages = wslDevShellTools ++ linuxLibraries;

              CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
              CARGO_BUILD_RUSTFLAGS =
                "-Ctarget-feature=+crt-static --cfg tracing_unstable";

              MODSECURITY = system-pkgs.libmodsecurity-linux-static;
              CORE_RULESET = core-ruleset;
              LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
              LIBCURL_PATH = "${system-pkgs.libcurl-linux-static}";
              LIBC_PATH = pkgs.musl.dev;

              BUSYBOX_GZIPPED = busybox-gzipped;
              NFT_GZIPPED = nft-gzipped;
              ZSH_GZIPPED = zsh-gzipped;
              PAMTESTER_GZIPPED = pamtester-gzipped;
            });
          };
        };
    };
}
