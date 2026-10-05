#!/bin/sh
set -e

FORCE=0
case "$1" in
    --force) FORCE=1 ;;
esac

STUDIO_PATH="/opt/vertigis-studio"
UPDATED=0
DID_SOMETHING=0

pkg_install() {
    if command -v apt-get >/dev/null 2>&1; then
        if [ "$UPDATED" = 0 ]; then
            sudo apt-get update
            UPDATED=1
        fi
        sudo apt-get install -y "$@"
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y "$@"
    else
        echo "No supported package manager (apt-get or dnf) found" >&2
        exit 1
    fi
}

# --- prerequisites ---
if [ "$FORCE" = 1 ] || ! command -v curl >/dev/null 2>&1; then
    echo "Installing curl..."
    pkg_install curl
    DID_SOMETHING=1
fi
if [ "$FORCE" = 1 ] || ! command -v setfacl >/dev/null 2>&1; then
    echo "Installing acl (for setfacl)..."
    pkg_install acl
    DID_SOMETHING=1
fi

# --- docker ---
if [ "$FORCE" = 1 ] || ! command -v docker >/dev/null 2>&1; then
    echo "Installing Docker (official convenience script) and adding $(id -un) to the docker group..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$(id -un)"
    DID_SOMETHING=1
fi

# --- /opt/vertigis-studio ---
studio_ready() {
    [ -d "$STUDIO_PATH" ] &&
        [ "$(stat -c '%G' "$STUDIO_PATH" 2>/dev/null)" = docker ] &&
        [ "$(stat -c '%A' "$STUDIO_PATH" 2>/dev/null | cut -c5-7)" = rws ] &&
        getfacl --omit-header "$STUDIO_PATH" 2>/dev/null | grep -qx 'default:group::rwx'
}

if [ "$FORCE" = 1 ] || ! studio_ready; then
    echo "Setting up $STUDIO_PATH (group docker, setgid, default ACL)..."
    sudo mkdir -p "$STUDIO_PATH"
    sudo chgrp docker "$STUDIO_PATH"
    sudo chmod g+ws "$STUDIO_PATH"
    sudo setfacl -m d:g::rwx "$STUDIO_PATH"
    DID_SOMETHING=1
fi

if [ "$DID_SOMETHING" = 0 ]; then
    echo "Already fully provisioned; nothing to do."
fi
