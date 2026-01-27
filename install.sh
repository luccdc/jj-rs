#!/usr/bin/env sh
set -e
# Install jiujitsu and friends
# This script is meant to be run from the tools tarball!

DEFAULT_PREFIX="/jj"

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    cat<<EOF
Install Jiujitsu and all the tools it comes with,
and ensure the installation path is on path.

Usage:
    $0 [prefix]

Arguments:
    prefix      The prefix to install to. Default: $DEFAULT_PREFIX
EOF
    exit
fi

IN=${1%%/}
PREFIX=${IN:-$DEFAULT_PREFIX}

add_prefix_to_path () {
    [ echo "export PATH=$PREFIX:\$PATH" >> ~/.profile ] &&
        echo "Added prefix to path!" && source ~/.profile ||
            echo "Unable to add prefix to path!"
}

if [ ! -d "$PREFIX" ]; then
    mkdir -p "$PREFIX"
fi

echo "Installing tools to $PREFIX"

install -m755 ./jj-bin/* $PREFIX

echo "Tools installed. Configuring path"


case :$PATH:
in *:$PREFIX:*)  echo "Prefix found on path! Not adding prefix to path.";;
  *) echo "Prefix not on path!" && add_prefix_to_path
esac
