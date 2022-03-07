#
# Distribution version discovery
#
# Copyright (C) 2014 Red Hat
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

if [ -z ${_DISTRO_SH+set} ]; then
declare -r _DISTRO_SH=

# Distribution family (lowercase)
declare DISTRO_FAMILY=
# Distribution ID (lowercase)
declare DISTRO_ID=
# Distribution release (lowercase)
declare DISTRO_RELEASE=

if [ -e /etc/redhat-release ]; then
    DISTRO_FAMILY=redhat
elif [ -e /etc/debian_version ]; then
    DISTRO_FAMILY=debian
else
    DISTRO_FAMILY=unknown
fi
declare -r DISTRO_FAMILY

. /etc/os-release
DISTRO_ID=$ID
declare -r DISTRO_ID
DISTRO_RELEASE=$VERSION_ID
declare -r DISTRO_RELEASE

if [ -f /.dockerenv ]; then
    IN_CONTAINER=true
fi

# Distribution branch (lowercase)
declare -r DISTRO_BRANCH="-$DISTRO_FAMILY-$DISTRO_ID-$DISTRO_RELEASE-"

function container_pre_install()
{
    echo "Pre-installing any required packages for containers on: "
    case $DISTRO_ID in
        fedora)
          echo "Fedora distro"
          dnf install -y git
          ;;
        ubuntu | debian)
          echo "Debian based distro"
          echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
          DEBIAN_FRONTEND=noninteractive apt-get --yes update
          DEBIAN_FRONTEND=noninteractive apt-get install -y dialog sudo rpm git
          ;;
        *)
          echo "Unknown distro, skipping"
          ;;
    esac
}

# Install packages.
# Args: [pkg_name...]
function distro_pkg_install()
{
    # install container pre-requisites
    if [ -n "$IN_CONTAINER" ]; then
        container_pre_install
    fi

    declare prompt=$'Need root permissions to install packages.\n'
    prompt+="Enter sudo password for $USER: "
    if [[ "$DISTRO_BRANCH" == -redhat-fedora-2[2-5]* ]]; then
        # TODO switch fedora to DNF once
        # https://bugzilla.redhat.com/show_bug.cgi?id=1215208 is fixed
        [ $# != 0 ] && sudo -p "$prompt" \
                            yum-deprecated --assumeyes install -- "$@" |&
            # Pass input to output, fail if a missing package is reported
            awk 'BEGIN {s=0}
                 /^No package .* available.$/ {s=1}
                 {print}
                 END {exit s}'
    elif [[ "$DISTRO_BRANCH" == -redhat-fedora-* ]]; then
        [ $# != 0 ] && sudo -p "$prompt" \
                            /usr/bin/dnf --assumeyes --best \
                                         --setopt=install_weak_deps=False \
                                         install -- "$@"
    elif [[ "$DISTRO_BRANCH" == -redhat-* ]]; then
        [ $# != 0 ] && sudo -p "$prompt" yum --assumeyes install -- "$@" |&
            # Pass input to output, fail if a missing package is reported
            awk 'BEGIN {s=0}
                 /^No package .* available.$/ {s=1}
                 {print}
                 END {exit s}'
    elif [[ "$DISTRO_BRANCH" == -debian-* ]]; then
        [ $# != 0 ] && DEBIAN_FRONTEND=noninteractive \
                       # Ensure updated apt cache
                       sudo -p "$prompt" apt-get --yes update \
                    && DEBIAN_FRONTEND=noninteractive \
                       sudo -p "$prompt" apt-get --yes install -- "$@"
    else
        echo "Cannot install packages on $DISTRO_BRANCH" >&2
        exit 1
    fi
}

# Remove packages.
# Args: [pkg_name...]
function distro_pkg_remove()
{
    declare prompt=$'Need root permissions to remove packages.\n'
    prompt+="Enter sudo password for $USER: "
    if [[ "$DISTRO_BRANCH" == -redhat-* ]]; then
        [ $# != 0 ] && sudo -p "$prompt" yum --assumeyes remove -- "$@"
    elif [[ "$DISTRO_BRANCH" == -debian-* ]]; then
        [ $# != 0 ] && sudo -p "$prompt" apt-get --yes remove -- "$@"
    else
        echo "Cannot remove packages on $DISTRO_BRANCH" >&2
        exit 1
    fi
}

fi # _DISTRO_SH
