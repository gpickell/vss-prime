"""Ensure the user has an ed25519 SSH key, generating one if they don't.

Uses the user's own ~/.ssh/id_ed25519 -- not a separate vss-prime-owned
key -- so it's whatever identity they already use (or will use) for SSH
everywhere else, including anything already authorized on remote hosts.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .sshinstall import find_ssh

SSH_DIR = Path.home() / ".ssh"
PRIVATE_KEY_PATH = SSH_DIR / "id_ed25519"
PUBLIC_KEY_PATH = SSH_DIR / "id_ed25519.pub"


def _find_ssh_keygen() -> Optional[str]:
    ssh = find_ssh()
    if ssh:
        candidate = Path(ssh).with_name("ssh-keygen.exe")
        if candidate.exists():
            return str(candidate)
    return shutil.which("ssh-keygen")


def has_key() -> bool:
    return PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists()


def generate_key() -> None:
    if has_key():
        return

    keygen = _find_ssh_keygen()
    if not keygen:
        raise RuntimeError("ssh-keygen not found; install OpenSSH first")

    SSH_DIR.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [keygen, "-t", "ed25519", "-f", str(PRIVATE_KEY_PATH), "-N", ""],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"ssh-keygen failed: {result.stderr.strip()}")


def ensure_key() -> bool:
    """Ensure the user has an ed25519 key, generating one if missing.
    Returns True if the key is present afterward."""
    if not has_key():
        print(f"No SSH key found at {PRIVATE_KEY_PATH}; generating a new ed25519 keypair...")
        generate_key()
    return has_key()
