"""Local settings, scratch, and cert-staging storage.

Shared under %ProgramData%\\vss-prime\\<user>, not the user's own profile
(~/.vss-prime, the original design). That broke in practice: an elevated
subprocess (certreq, via winsudo) doesn't necessarily run as *this* same
user elevated -- hardened environments commonly require a separate,
dedicated admin account for elevation, with no ACL access to another
user's profile folder at all. %ProgramData% is the standard shared
location for exactly this; we just have to set its ACL ourselves since
we're the ones creating it here, not an admin installer.
"""
from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
from typing import Any

from . import winsudo

_PROGRAM_DATA = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
BASE_DIR = _PROGRAM_DATA / "vss-prime"

_USER = getpass.getuser()
SETTINGS_DIR = BASE_DIR / _USER
SETTINGS_FILE = SETTINGS_DIR / "settings.json"
SCRATCH_DIR = SETTINGS_DIR / "scratch"

# BUILTIN\Administrators as a well-known SID, not the (localized) group
# name -- works regardless of display language.
_ADMINISTRATORS_SID = "*S-1-5-32-544"


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _ensure_shared_dir() -> None:
    """Create BASE_DIR and SETTINGS_DIR if missing, granting
    Administrators Full Control on the shared root -- (OI)(CI) so any
    per-user subfolder created afterward inherits it too, covering
    whichever admin account elevation actually uses -- and this user
    Full Control on their own subfolder underneath it, so normal
    (unelevated) reads/writes keep working without prompting every
    time. Elevated: a standard user can't normally create new top-level
    folders under %ProgramData%. Only runs once per user -- skipped
    entirely once SETTINGS_DIR already exists.
    """
    if SETTINGS_DIR.exists():
        return

    script = (
        f"New-Item -ItemType Directory -Force -Path {_ps_quote(str(BASE_DIR))} | Out-Null; "
        f"icacls {_ps_quote(str(BASE_DIR))} /grant "
        f"{_ps_quote(_ADMINISTRATORS_SID + ':(OI)(CI)F')} | Out-Null; "
        f"New-Item -ItemType Directory -Force -Path {_ps_quote(str(SETTINGS_DIR))} | Out-Null; "
        f"icacls {_ps_quote(str(SETTINGS_DIR))} /grant {_ps_quote(_USER + ':(OI)(CI)F')} | Out-Null"
    )
    exit_code = winsudo.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
    if exit_code != 0:
        raise RuntimeError(f"Setting up {SETTINGS_DIR} failed with exit code {exit_code}")


def _load() -> dict:
    if not SETTINGS_FILE.exists():
        return {}
    return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))


def _save(data: dict) -> None:
    _ensure_shared_dir()
    SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_setting(key: str, default: Any = None) -> Any:
    return _load().get(key, default)


def set_setting(key: str, value: Any) -> None:
    data = _load()
    data[key] = value
    _save(data)


def ensure_scratch_dir() -> Path:
    _ensure_shared_dir()
    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    return SCRATCH_DIR
