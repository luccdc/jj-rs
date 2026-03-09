{ nixpkgs, system ? "x86_64-linux", pkgs ? import <nixpkgs> { inherit system; }
, winPkgs ? import <nixpkgs> {
  localSystem = system;
  crossSystem = {
    config = "x86_64-w64-mingw32";
    libc = "msvcrt";
  };
}, winpthreads }: rec {
  libpcap-linux-static = pkgs.stdenv.mkDerivation {
    name = "libpcap-linux-static";

    buildInputs = with pkgs; [ clang automake bison cmake flex musl ];

    src = pkgs.fetchFromGitHub {
      owner = "the-tcpdump-group";
      repo = "libpcap";
      rev = "libpcap-1.10.6";
      hash = "sha256-rth3eIIj1h5Sl5wQ1enM2CcnckOQhahbOciU2YDjLBo=";
      fetchSubmodules = false;
    };

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

  libcurl-linux-static = pkgs.stdenv.mkDerivation {
    name = "libcurl-linux-static";

    buildInputs = with pkgs; [
      pkgsCross.musl64.buildPackages.clang
      autoconf
      automake
      libtool
      cmake
      pkg-config
      pkgsStatic.aws-lc
      pkgsStatic.libpsl
    ];

    src = pkgs.fetchFromGitHub {
      owner = "curl";
      repo = "curl";
      rev = "curl-8_18_0";
      hash = "sha256-OGJp9VN8hiLe05gb6FQcRozRg+mcZBl286ahiawvqMM=";
    };

    configurePhase = ''
      export CC=x86_64-unknown-linux-musl-clang
      export CXX=x86_64-unknown-linux-musl-clang++
      cmake \
            -DCMAKE_BUILD_TYPE=MinSizeRel \
            -DBUILD_CURL_EXE=OFF \
            -DBUILD_EXAMPLES=OFF \
            -DBUILD_LIBCURL_DOCS=OFF \
            -DBUILD_MISC_DOCS=OFF \
            -DBUILD_SHARED_LIBS=OFF \
            -DBUILD_STATIC_CURL=OFF \
            -DBUILD_STATIC_LIBS=ON \
            -DBUILD_TESTING=OFF \
            -DCURL_DROP_UNUSED=ON \
            -DCURL_ENABLE_SSL=ON \
            -DCURL_USE_OPENSSL=ON \
            -DCURL_USE_LIBUV=OFF \
            -DCURL_DISABLE_ALTSVC=ON \
            -DCURL_DISABLE_DICT=ON \
            -DCURL_DISABLE_GOPHER=ON \
            -DCURL_DISABLE_IMAP=ON \
            -DCURL_DISABLE_LDAP=ON \
            -DCURL_DISABLE_LDAPS=ON \
            -DCURL_DISABLE_RTSP=ON \
            -DCURL_DISABLE_SMTP=ON \
            -DCURL_DISABLE_SRP=ON \
            -DCURL_DISABLE_TELNET=ON \
            -DCURL_DISABLE_TFTP=ON \
            -DCURL_DISABLE_TFTP=ON \
            -DCURL_DISABLE_MQTT=ON \
            -DCURL_DISABLE_NETRC=ON \
            -DCURL_DISABLE_NTLM=ON \
            -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG=ON \
            -DUSE_NGHTTP2=OFF \
            -DUSE_NGTCP2=OFF \
            -DUSE_QUICHE=OFF \
            -DUSE_LIBSSH2=OFF \
            -DUSE_ZSTD=OFF \
            -DOPENSSL_USE_STATIC_LIBS=ON \
            -DZLIB_USE_STATIC_LIBS=ON \
            -DCMAKE_INSTALL_PREFIX=$out \
            .
    '';
  };

  libmodsecurity-linux-static = pkgs.stdenv.mkDerivation {
    name = "libmodsecurity-linux-static";

    nativeBuildInputs = with pkgs; [
      pkgsCross.musl64.buildPackages.clang
      pkgsCross.musl64.buildPackages.lld
      autoconf
      automake
      libtool
      pkg-config
      autoconf-archive
      flex
      bison
      pkgsStatic.pcre
      pkgsStatic.yajl
      pkgsStatic.aws-lc
      pkgsStatic.libpsl
      pkgsStatic.libidn2
      pkgsStatic.libunistring
      pkgsStatic.libcxx
      libcurl-linux-static
    ];

    src = pkgs.fetchFromGitHub {
      owner = "owasp-modsecurity";
      repo = "ModSecurity";
      rev = "v3.0.14";
      hash = "sha256-SaeBO3+WvPhHiJoiOmijB0G3/QYxjAdxgeCVqESS+4U=";
      fetchSubmodules = true;
    };

    configurePhase = ''
      export CC=x86_64-unknown-linux-musl-clang
      export CXX=x86_64-unknown-linux-musl-clang++
      export CXXFLAGS="-nostdinc++ -nostdlib++ -isystem -lc++ -I${pkgs.pkgsStatic.libcxx.dev}/include/c++/v1 -L${pkgs.pkgsStatic.libcxx}/lib -Wl,-rpath,${pkgs.pkgsStatic.libcxx}/lib"
      export CPPFLAGS="-I${pkgs.pkgsStatic.pcre2.dev}/include"
      export LDFLAGS="-L${pkgs.pkgsStatic.pcre2.out}/lib -lpcre2-8"
      ./build.sh
      ./configure \
        --enable-static \
        --disable-shared \
        --prefix=$out \
        --with-curl=${libcurl-linux-static}
    '';
  };

  aws-lc-windows-static = pkgs.stdenv.mkDerivation {
    name = "aws-lc-windows-static";

    buildInputs = (with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      pkgsCross.mingwW64.buildPackages.nasm
      winpthreads
      autoconf
      automake
      libtool
      cmake
      pkg-config
      ninja
      perl
      go
    ]);

    src = pkgs.fetchFromGitHub {
      owner = "aws";
      repo = "aws-lc";
      rev = "v1.68.0";
      hash = "sha256-BUx2eOBW4kJMKebClf9+XjcUVUO3BCUKyBpFoB040Wo=";
    };

    configurePhase = ''
      export CC=x86_64-w64-mingw32-gcc
      export CFLAGS="-static"
      export CXX=x86_64-w64-mingw32-g++
      export CXXFLAGS="-static"
      export AR=x86_64-w64-mingw32-ar
      export RANLIB=x86_64-w64-mingw32-ranlib
      mkdir aws-lc-build && cd aws-lc-build
      cmake -GNinja \
            -DCMAKE_SYSTEM_NAME=Windows \
            -DCMAKE_BUILD_TYPE=MinSizeRel \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DBUILD_TESTING=OFF \
            -DBUILD_TOOL=OFF \
            -DARCH=x86_64 \
            -DCMAKE_ASM_NASM_COMPILER=nasm \
            -DCMAKE_ASM_NASM_FLAGS="-f win64" \
            -DCMAKE_SYSTEM_PROCESSORARCH=x86_64 \
            -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
            ..

      # by default it is set to windows 7, but setting -D_WIN32_WINNT_WIN7
      # doesn't allow changing it at all
      sed -i -e 's/_WIN32_WINNT_WIN7/0x0a00/g' build.ninja
    '';

    buildPhase = ''
      export HOME="$(mktemp -d)"
      ninja
    '';

    installPhase = ''
      ninja install
    '';
  };

  gnulib-source = pkgs.fetchgit {
    url = "git://git.savannah.gnu.org/gnulib.git";
    rev = "edf2e42f5f170f7e3dab78de25dcb67a7417fc97";
    hash = "sha256-hbywWti/WCPggix+jLkpJDosGuOrs8hdyvTRcixGxhE=";
  };

  libunistring-windows-static = pkgs.stdenv.mkDerivation {
    name = "libunistring-windows-static";

    buildInputs = with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      which
      git
      gettext
      autoconf
      automake
      libtool
      cmake
      libidn2
      python3
      wget
      pkg-config
      texinfo
      gperf
      perl
    ];

    src = pkgs.fetchgit {
      url = "https://git.savannah.gnu.org/git/libunistring.git";
      rev = "ad26ecf8f1c1317f6d1449ad3db20d3323fc10e4";
      hash = "sha256-Z04zcJcEMiy+NYpzpLW8f50siHeNKXsMwQSrlQ23++M=";
    };

    configurePhase = ''
      cp -r ${gnulib-source} gnulib

      ./autogen.sh

      cat <<EOD > tests/Makefile.in
      all:
      install:
      EOD

      ./configure \
           --prefix=$out \
           --enable-static \
           --disable-shared \
           --host=x86_64-w64-mingw32 \
           CC=x86_64-w64-mingw32-gcc \
           CXX=x86_64-w64-mingw32-g++ \
           CPPFLAGS="-I${pkgs.pkgsCross.mingwW64.windows.mingw_w64.dev}/include -Wall" \
           LDFLAGS="-L${pkgs.pkgsCross.mingwW64.windows.mingw_w64}/out"
    '';
  };

  libidn2-windows-static = pkgs.stdenv.mkDerivation {
    name = "libidn2-windows-static";

    buildInputs = with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      autoconf
      automake
      libtool
      python3
      pkg-config
      libunistring-windows-static
    ];

    src = builtins.fetchTarball {
      url = "https://ftp.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz";
      sha256 = "1d8cx2c00mfyaqwdnjnlvjz491fpqcrv7fdsdwhsz22kk4spcxsh";
    };

    configurePhase = ''
      export CC=x86_64-w64-mingw32-gcc
      export CXX=x86_64-w64-mingw32-g++
      ./configure \
           --prefix=$out \
           --enable-static \
           --disable-shared \
           --host=x86_64-w64-mingw32
    '';
  };

  libiconv-windows-static = pkgs.stdenv.mkDerivation {
    name = "libiconv-windows-static";

    buildInputs = with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      which
      gettext
      autoconf
      automake
      libtool
      python3
      pkg-config
      libidn2-windows-static
      libunistring-windows-static
    ];

    src = builtins.fetchTarball {
      url = "https://ftp.gnu.org/pub/gnu/libiconv/libiconv-1.18.tar.gz";
      sha256 = "0n6v0n0xiwgglmrbzlxxhdi7lf6iwdbbmi4m2dz44mqv0v6khbq5";
    };

    configurePhase = ''
      export CC=x86_64-w64-mingw32-gcc
      export CXX=x86_64-w64-mingw32-g++
      ./configure \
           --prefix=$out \
           --enable-static \
           --disable-shared \
           --host=x86_64-w64-mingw32
    '';
  };

  libpsl-windows-static = pkgs.stdenv.mkDerivation {
    name = "libpsl-windows-static";

    buildInputs = with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      which
      git
      gettext
      autoconf
      automake
      libtool
      python3
      pkg-config
      libiconv-windows-static
      libidn2-windows-static
      libunistring-windows-static
    ];

    src = pkgs.fetchFromGitHub {
      owner = "rockdaboot";
      repo = "libpsl";
      rev = "b87753fbe660316716569b64502b094085738949";
      hash = "sha256-rasNW25F5zwQQ/nWwx+ZXLpRKF1bZxb2oTTfrhvFeKk=";
      fetchSubmodules = true;
    };

    configurePhase = ''
      export CC=x86_64-w64-mingw32-gcc
      export CXX=x86_64-w64-mingw32-g++

      ./autogen.sh
      ./configure \
           --prefix=$out \
           --enable-static \
           --disable-shared \
           --host=x86_64-w64-mingw32 \
           --with-libunistring-prefix=${libunistring-windows-static} \
           --enable-runtime=libidn2 \
           --enable-builtin
    '';
  };

  libcurl-windows-static = pkgs.stdenv.mkDerivation {
    name = "libcurl-windows-static";

    buildInputs = with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      pkgsCross.mingwW64.buildPackages.clang
      autoconf
      automake
      libtool
      cmake
      pkg-config
      aws-lc-windows-static
      libpsl-windows-static
    ];

    src = pkgs.fetchFromGitHub {
      owner = "curl";
      repo = "curl";
      rev = "curl-8_18_0";
      hash = "sha256-OGJp9VN8hiLe05gb6FQcRozRg+mcZBl286ahiawvqMM=";
    };

    configurePhase = ''
      export CC=x86_64-w64-mingw32-gcc
      export CXX=x86_64-w64-mingw32-g++
      cmake \
            -DCMAKE_SYSTEM_NAME=Windows \
            -DBUILD_CURL_EXE=OFF \
            -DBUILD_EXAMPLES=OFF \
            -DBUILD_LIBCURL_DOCS=OFF \
            -DBUILD_MISC_DOCS=OFF \
            -DBUILD_SHARED_LIBS=OFF \
            -DBUILD_STATIC_CURL=OFF \
            -DBUILD_STATIC_LIBS=ON \
            -DBUILD_TESTING=OFF \
            -DCURL_DROP_UNUSED=ON \
            -DCURL_ENABLE_SSL=ON \
            -DCURL_USE_OPENSSL=ON \
            -DCURL_USE_LIBUV=OFF \
            -DCURL_DISABLE_ALTSVC=ON \
            -DCURL_DISABLE_DICT=ON \
            -DCURL_DISABLE_GOPHER=ON \
            -DCURL_DISABLE_IMAP=ON \
            -DCURL_DISABLE_LDAP=ON \
            -DCURL_DISABLE_LDAPS=ON \
            -DCURL_DISABLE_RTSP=ON \
            -DCURL_DISABLE_SMTP=ON \
            -DCURL_DISABLE_SRP=ON \
            -DCURL_DISABLE_TELNET=ON \
            -DCURL_DISABLE_TFTP=ON \
            -DCURL_DISABLE_TFTP=ON \
            -DCURL_DISABLE_MQTT=ON \
            -DCURL_DISABLE_NETRC=ON \
            -DCURL_DISABLE_NTLM=ON \
            -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG=ON \
            -DUSE_NGHTTP2=OFF \
            -DUSE_NGTCP2=OFF \
            -DUSE_QUICHE=OFF \
            -DUSE_LIBSSH2=OFF \
            -DUSE_ZSTD=OFF \
            -DOPENSSL_USE_STATIC_LIBS=ON \
            -DZLIB_USE_STATIC_LIBS=ON \
            -DCMAKE_INSTALL_PREFIX=$out \
            .
    '';
  };

  libpcre-windows-static = pkgs.stdenv.mkDerivation {
    name = "libpcre-windows-static";

    nativeBuildInputs = with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      autoconf
      automake
      libtool
      pkg-config
    ];

    src = builtins.fetchTarball {
      url =
        "https://cytranet-dal.dl.sourceforge.net/project/pcre/pcre/8.45/pcre-8.45.tar.gz";
      sha256 = "1pp6k7c4v3d4is8kj4z6rbmxkl2nq84d2rr767snr7qlymmmsnxi";
    };

    configurePhase = ''
      export CC=x86_64-w64-mingw32-gcc
      export CXX=x86_64-w64-mingw32-g++
      ./configure \
             --disable-shared \
             --enable-static \
             --host=x86_64-w64-mingw32 \
             --prefix=$out
    '';
  };

  libxml2-windows-static = pkgs.stdenv.mkDerivation {
    name = "libxml2-windows-static";

    nativeBuildInputs = with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      autoconf
      automake
      libtool
      cmake
      pkg-config
      libiconv-windows-static
    ];

    src = pkgs.fetchFromGitHub {
      owner = "GNOME";
      repo = "libxml2";
      rev = "v2.15.1";
      hash = "sha256-FUfYMq5xT2i88JdIw9OtSofraUL3yjsyOVund+mfJKQ=";
    };

    configurePhase = ''
      export CC=x86_64-w64-mingw32-gcc
      export CXX=x86_64-w64-mingw32-g++
      cmake \
            -DCMAKE_SYSTEM_NAME=Windows \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DBUILD_SHARED_LIBS=OFF \
            -DLIBXML2_WITH_THREADS=OFF \
            .
    '';
  };

  # only needed on Windows... and only needed to emulate glob patterns
  libpoco-windows-static = pkgs.stdenv.mkDerivation {
    name = "libpoco-windows-static";

    nativeBuildInputs = with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      winpthreads
      which
      autoconf
      automake
      libtool
      cmake
      pkg-config
    ];

    src = pkgs.fetchFromGitHub {
      owner = "pocoproject";
      repo = "poco";
      rev = "poco-1.15.0-release";
      hash = "sha256-SPUyYV3iix+myobGLhU2cSDVDZOhnaftGEK9fLwh7js=";
    };

    configurePhase = ''
      export CC=x86_64-w64-mingw32-gcc
      export CXX=x86_64-w64-mingw32-g++

      mkdir tmp-utils
      ln -s $(which x86_64-w64-mingw32-windmc) tmp-utils/mc.exe
      export PATH="$PWD/tmp-utils:$PATH"

      which mc.exe

      cmake \
            -DCMAKE_SYSTEM_NAME=Windows \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DBUILD_SHARED_LIBS=OFF \
            -DCMAKE_BUILD_TYPE=MinSizeRel \
            -DENABLE_ACTIVERECORD=OFF \
            -DENABLE_ACTIVERECORD_COMPILER=OFF \
            -DENABLE_DATA=OFF \
            -DENABLE_DATA_ODBC=OFF \
            -DENABLE_DATA_SQLITE=OFF \
            -DENABLE_ENCODINGS=OFF \
            -DENABLE_FASTLOGGER=OFF \
            -DENABLE_JSON=OFF \
            -DENABLE_MONGODB=OFF \
            -DENABLE_NET=OFF \
            -DENABLE_PAGECOMPILER=OFF \
            -DENABLE_PAGECOMPILER_FILE2PAGE=OFF \
            -DENABLE_PROMETHEUS=OFF \
            -DENABLE_REDIS=OFF \
            -DENABLE_UTIL=OFF \
            -DENABLE_XML=OFF \
            -DENABLE_ZIP=OFF \
            -DPOCO_SOO=OFF \
            .
    '';
  };

  libmcfgthread-windows-static = pkgs.stdenv.mkDerivation {
    name = "libmcfgthread-windows-static";

    nativeBuildInputs = with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      winpthreads
      autoconf
      automake
      libtool
      meson
      ninja
      pkg-config
    ];

    src = pkgs.fetchFromGitHub {
      owner = "lhmouse";
      repo = "mcfgthread";
      rev = "v2.3-ga.1";
      hash = "sha256-x20wmqm675+pFx+eOu2zWA3BZsG+TXgBTwOoc6+I7WA=";
    };

    configurePhase = ''
      meson setup \
            --prefix $out \
            --default-library static \
            --default-both-libraries static \
            --cross-file cross/gcc.x86_64-w64-mingw32 \
            build
    '';

    buildPhase = ''
      cd build
      ninja
    '';

    fixupPhase = ''
      rm $out/lib/libmcfgthread.dll.a
    '';
  };

  libmodsecurity-windows-static = pkgs.stdenv.mkDerivation {
    name = "libmodsecurity-windows-static";

    nativeBuildInputs = with pkgs; [
      pkgsCross.mingwW64.buildPackages.gcc
      winpthreads
      autoconf
      automake
      libtool
      cmake
      pkg-config
      libpcre-windows-static
      aws-lc-windows-static
      libpsl-windows-static
      libidn2-windows-static
      libxml2-windows-static
      libunistring-windows-static
      libiconv-windows-static
      libmcfgthread-windows-static
    ];

    src = pkgs.fetchFromGitHub {
      owner = "owasp-modsecurity";
      repo = "ModSecurity";
      rev = "v3.0.14";
      hash = "sha256-SaeBO3+WvPhHiJoiOmijB0G3/QYxjAdxgeCVqESS+4U=";
      fetchSubmodules = true;
    };

    configurePhase = ''
      export CC=x86_64-w64-mingw32-gcc
      export CXX=x86_64-w64-mingw32-g++
      export CFLAGS="-D_WINDOWS -DWIN32 -D_WIN32"
      export CPPFLAGS="-I${pkgs.pkgsCross.mingwW64.windows.mingw_w64_headers}/include -I${pkgs.pkgsStatic.pcre2.dev}/include $CFLAGS"
      export LDFLAGS="-L${pkgs.pkgsStatic.pcre2.out}/lib -lpcre2-8"

      sed -i '/case \$host in/a\
        *mingw32*)\
          echo "Checking platform... Identified as Windows"\
          AC_DEFINE([WINDOWS], [1], [Define if the operating system is Windows])\
          PLATFORM="Windows"\
          ;;\
      ' configure.ac

      # Windows allows case insensitive file names... of course
      grep -Rl WinSock2.h . | xargs -I{} sed -i -e 's/WinSock2.h/winsock2.h/' {}
      grep -Rl WS2tcpip.h . | xargs -I{} sed -i -e 's/WS2tcpip.h/ws2tcpip.h/' {}
      grep -Rl Windows.h . | xargs -I{} sed -i -e 's/Windows.h/windows.h/' {}

      # src/utils/system.cc does not import Windows headers if compiling with mingw32
      sed -i 's/_MSC_VER/WIN32/' src/utils/system.cc
      # it also uses a poorly written isFile function
      awk -i inplace '/#include/ { if (!set) { print "#include <filesystem>"; set = 1; } } 1' src/utils/system.cc
      awk -i inplace '/#include/ { if (!set) { print "#include <system_error>"; set = 1; } } 1' src/utils/system.cc
      sed -i '/bool isFile/,$d' src/utils/system.cc
      cat <<EOD >> src/utils/system.cc
      bool isFile(const std::string& f) {
           std::filesystem::path p(f);
           std::error_code e;
           return std::filesystem::is_regular_file(p, e);
      }
      }
      }
      EOD

      # it also imports an entire library for glob, but we don't use glob
      sed -i 's/Poco::Glob::glob(var, files)/files.emplace(var)/' src/utils/system.cc
      # ...but the header file imported for Poco also imports a standard Windows API...
      sed -i 's/Poco\/Glob.h/processthreadsapi.h/' src/utils/system.cc

      ./build.sh
      ./configure \
        --enable-static \
        --disable-shared \
        --prefix=$out \
        --host=x86_64-w64-mingw32 \
        --with-curl=${libcurl-windows-static}

      # Don't build any programs, just libraries
      cat <<EOD > Makefile.empty
      all:
      	echo Skipping build
      install:
      	echo Skipping install

      .PHONY: all
      EOD
      cp Makefile.empty tools/rules-check/Makefile
      cp Makefile.empty examples/Makefile
    '';
  };
}
