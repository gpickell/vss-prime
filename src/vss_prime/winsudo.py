"""Windows elevation ("sudo") facility.

Delegates actual elevation to gsudo (https://github.com/gerardog/gsudo),
installed via winget if missing. gsudo already solves the hard problems
involved in doing this well: it keeps a hidden, elevated broker alive
after the first UAC prompt and shares the console with every command it
runs for you (via handle duplication into the broker), instead of either
re-prompting per command (ShellExecuteExW + "runas", tried previously)
or needing privileges an ordinary process doesn't hold
(CreateProcessAsUser / CreateProcessWithLogonW, both tried and rejected
-- see PLAN.md for why).

Trade-off: elevation now depends on a third-party binary with elevated-
execution capability, rather than ~150 lines of ctypes we fully control.
"""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
from ctypes import wintypes
from typing import Dict, Optional, Sequence, Tuple

GSUDO_PACKAGE_ID = "gerardog.gsudo"

# How long the elevation cache stays valid while idle (gsudo's own
# default is 5 minutes); resets on each use, so this is a ceiling on
# idle time between privileged actions, not a hard session length.
CACHE_DURATION = "01:00:00"

# "net session" requires administrator rights and makes no changes: it is
# the classic, side-effect-free way to prove elevation actually works
# (a non-admin token gets "Access is denied", exit code != 0).
PROBE_COMMAND: Sequence[str] = ("net.exe", "session")

# Interactive shells/terminal hosts: process-ancestry walking stops here
# rather than at whatever immediate wrapper (a launcher trampoline, `uv
# run`, etc.) happens to be our direct parent, since those are often
# short-lived and recreated on every invocation.
_SHELL_NAMES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe",
    "windowsterminal.exe", "conhost.exe",
}

_TH32CS_SNAPPROCESS = 0x00000002
_MAX_PATH = 260


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * _MAX_PATH),
    ]


_kernel32_th32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32_th32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_kernel32_th32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_kernel32_th32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
_kernel32_th32.Process32FirstW.restype = wintypes.BOOL
_kernel32_th32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
_kernel32_th32.Process32NextW.restype = wintypes.BOOL
_kernel32_th32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32_th32.CloseHandle.restype = wintypes.BOOL

_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _process_table() -> Dict[int, Tuple[int, str]]:
    """pid -> (parent pid, exe name) for every running process."""
    table: Dict[int, Tuple[int, str]] = {}
    snapshot = _kernel32_th32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == _INVALID_HANDLE_VALUE:
        return table
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if not _kernel32_th32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return table
        while True:
            table[entry.th32ProcessID] = (entry.th32ParentProcessID, entry.szExeFile)
            if not _kernel32_th32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        _kernel32_th32.CloseHandle(snapshot)
    return table


def _terminal_pid() -> int:
    """Walk our process ancestry past wrapper/launcher processes (a
    console-script trampoline, `uv run`, etc.) to the nearest actual
    shell/terminal host, so the gsudo cache scope survives across
    separate `vss-prime` invocations from the same terminal session
    instead of just our own (possibly short-lived-wrapper-adjacent)
    process. Falls back to the immediate parent if the walk can't find
    a recognized shell (e.g. an unknown terminal emulator)."""
    table = _process_table()
    pid = os.getppid()
    best = pid
    seen: set = set()
    while pid and pid in table and pid not in seen:
        seen.add(pid)
        best = pid
        parent_pid, name = table[pid]
        if name.lower() in _SHELL_NAMES:
            return pid
        if not parent_pid or parent_pid == pid:
            break
        pid = parent_pid
    return best


class ElevationError(RuntimeError):
    """Raised when gsudo can't be found/installed, or an elevated command
    fails."""


def find_gsudo() -> Optional[str]:
    return shutil.which("gsudo")


def _refresh_path_from_registry() -> None:
    """winget updates the persisted user/machine PATH in the registry;
    this already-running process won't see that until something re-reads
    it. Pull the current values and merge in anything new so a package
    installed moments ago is found without restarting the process."""
    import winreg

    entries = os.environ.get("PATH", "").split(os.pathsep)
    seen = {e.lower() for e in entries if e}

    for hive, subkey in (
        (winreg.HKEY_CURRENT_USER, r"Environment"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
    ):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                value, _ = winreg.QueryValueEx(key, "Path")
        except OSError:
            continue
        for entry in value.split(os.pathsep):
            if entry and entry.lower() not in seen:
                entries.append(entry)
                seen.add(entry.lower())

    os.environ["PATH"] = os.pathsep.join(entries)


def install_gsudo() -> None:
    """Install gsudo via winget. ``--scope user`` matters: without it,
    winget picks gsudo's admin-elevated MSI installer; with it, winget
    uses the portable zip distribution instead, installed per-user with
    no elevation needed."""
    result = subprocess.run(
        [
            "winget", "install", "--id", GSUDO_PACKAGE_ID, "-e", "--scope", "user",
            "--accept-package-agreements", "--accept-source-agreements",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ElevationError(
            f"gsudo install failed (winget exit {result.returncode}): {result.stderr.strip()}"
        )


def ensure_gsudo() -> str:
    """Return a path to gsudo, installing it via winget if missing."""
    gsudo = find_gsudo()
    if gsudo:
        return gsudo

    # Not on PATH yet doesn't mean not installed -- a prior install (this
    # process, a previous run, or the user doing it themselves) lands in
    # the registry immediately but this process's PATH is stale until
    # something re-reads it. Check that before deciding to (re)install.
    _refresh_path_from_registry()
    gsudo = find_gsudo()
    if gsudo:
        return gsudo

    install_gsudo()
    _refresh_path_from_registry()
    gsudo = find_gsudo()
    if not gsudo:
        raise ElevationError("gsudo still not found on PATH after install")
    return gsudo


def run(args: Sequence[str]) -> int:
    """Run ``args`` elevated via gsudo, sharing this console.

    Lazily warms up the cache (ensure_sudo()) first: without it, every
    single call here would hit gsudo's own default CacheMode=Explicit
    and pop its own fresh UAC prompt, regardless of --sudo having been
    passed -- the cache has to actually be started somewhere, and
    --sudo is only an optional eager pre-warm, not the only path here.
    """
    ensure_sudo()
    gsudo = ensure_gsudo()
    result = subprocess.run([gsudo, *args])
    return result.returncode


def capture(args: Sequence[str]) -> Tuple[int, str]:
    """Run ``args`` elevated via gsudo, returning (exit code, combined
    stdout+stderr) instead of sharing this console -- for commands whose
    output needs parsing (e.g. certreq), not just their exit code.

    Unlike ``run()``, a nonzero exit isn't necessarily a failure here --
    certreq in particular uses nonzero exits for legitimate non-error
    dispositions (e.g. a request taken under submission) -- so this
    doesn't raise on its own; the caller interprets exit code + output
    together. Also lazily warms up the cache first, same as run().
    """
    ensure_sudo()
    gsudo = ensure_gsudo()
    result = subprocess.run(
        [gsudo, *args], capture_output=True, text=True
    )
    return result.returncode, result.stdout + result.stderr


def _run_quiet(args: Sequence[str]) -> int:
    """Like ``run()``, but discards the elevated command's own output --
    for internal checks (e.g. the probe) whose output isn't meaningful
    to the user."""
    gsudo = ensure_gsudo()
    result = subprocess.run([gsudo, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode


def _enable_cache() -> None:
    """Start a gsudo credentials cache session scoped to our parent (the
    terminal/shell that launched us), not just this process.

    gsudo's default CacheMode is "Explicit": without an active cache
    session, every single elevated call pops its own UAC prompt. This
    starts one (itself requiring the one UAC prompt per process we want)
    so every later ``run()`` reuses it -- not just in this process, but
    in any later `vss-prime` run from the same terminal session too,
    since gsudo's cache lookup covers the scoped process and whatever it
    spawns. Deliberately not changing gsudo's global CacheMode config --
    that would affect the user's own unrelated uses of gsudo too.
    """
    gsudo = ensure_gsudo()
    scope_pid = _terminal_pid()
    # gsudo prints a (correct, but repetitive for us) security warning on
    # every "cache on" at its default LogLevel; Error drops it without
    # hiding actual errors.
    result = subprocess.run(
        [
            gsudo, "--loglevel", "Error", "cache", "on",
            "-p", str(scope_pid), "-d", CACHE_DURATION,
        ]
    )
    if result.returncode != 0:
        raise ElevationError(f"Enabling the sudo cache failed with exit code {result.returncode}")


_verified = False


def ensure_sudo() -> None:
    """Prove elevation (and its cache) works, once per process. Every
    later call is a no-op; the cache setup and probe only run once."""
    global _verified
    if _verified:
        return

    print("Warming up elevation (gsudo) -- may prompt for admin confirmation once; later privileged actions reuse it...")
    _enable_cache()
    exit_code = _run_quiet(PROBE_COMMAND)
    if exit_code != 0:
        raise ElevationError(f"Elevation probe failed with exit code {exit_code}")
    _verified = True
