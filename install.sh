#!/usr/bin/env sh
# Install jiujitsu and friends
set -eu

DEFAULT_PREFIX="/usr/local/jj"
PREFIX=${1:-${DEFAULT_PREFIX}}

if [ "${PREFIX}" = "--help" ] || [ "${PREFIX}" = "-h" ]; then
    cat<<HELPMSG
Install Jiujitsu and all the tools it comes with,
and ensure the installation path is on path.

Usage:
    $0 [prefix]

Arguments:
    prefix      The prefix to install to.
                Default: ${DEFAULT_PREFIX}
HELPMSG
    exit 0
fi

if [ ! -d ./jj-bin ]; then
    printf 'Unable to find jj-bin/ in directory!\n'
    printf 'Please run me from the same directory you unziped jj.tgz in!\n'
    exit 1
fi

(set -x
 mkdir -p "${PREFIX}"
 install -m755 ./jj-bin/* "${PREFIX}"
)

# Next, add the prefix to path if possible.
case :${PATH}:
in *:${PREFIX}:*)  printf "Prefix found on path! Not adding prefix to path.\n";;
  *) {
      printf "Adding path to profile files...\n"
      printf "export PATH=%s:\${PATH}\n" "${PREFIX}" | tee -a ~/.profile ~/.zprofile

      [ -d /etc/sudoers.d ] && 
          printf 'Defaults   secure_path = "%s:/bin:/sbin:/usr/bin:/usr/sbin"\n' "${PREFIX}" >> /etc/sudoers.d/jj
  }
esac

printf "\nBe sure to run '. ~/.profile' to pick up changes\n"
