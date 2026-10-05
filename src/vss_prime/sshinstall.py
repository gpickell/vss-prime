"""Ensure the Windows OpenSSH client is available, installing it via the
elevation facility (winsudo) if it's missing."""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional

from . import winsudo

_CAPABILITY_NAME = "OpenSSH.Client~~~~0.0.1.0"
_DEFAULT_SSH_PATH = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "OpenSSH" / "ssh.exe"


def find_ssh() -> Optional[str]:
    """Return a usable path to ssh.exe, or None if it isn't installed.

    Checks PATH first, then OpenSSH's fixed install location -- useful
    right after installing it in this same process, before PATH is
    refreshed."""
    on_path = shutil.which("ssh")
    if on_path:
        return on_path
    if _DEFAULT_SSH_PATH.exists():
        return str(_DEFAULT_SSH_PATH)
    return None


def is_installed() -> bool:
    return find_ssh() is not None


def install() -> None:
    """Install the OpenSSH client Windows capability (requires elevation)."""
    command = (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        f"Add-WindowsCapability -Online -Name {_CAPABILITY_NAME}",
    )
    exit_code = winsudo.run(command)
    if exit_code != 0:
        raise RuntimeError(f"OpenSSH install failed with exit code {exit_code}")


def ensure_ssh(force: bool = False) -> bool:
    """Ensure ssh is installed, installing (or reinstalling, if ``force``)
    it as needed. Returns True if ssh is available afterward."""
    if not force and is_installed():
        return True
    print("Installing the OpenSSH client Windows capability (elevated -- may prompt)...")
    install()
    return is_installed()
