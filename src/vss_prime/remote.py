"""Run commands on a remote host over SSH, sharing this console.

The remote equivalent of winsudo.run(): given a profile name (a Host
alias already set up via sshprofile, with HostName/User/IdentityFile/
HostKeyAlias all resolved from ~/.ssh/config), run a command there.
"""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Sequence

from .sshinstall import find_ssh


class RemoteExecError(RuntimeError):
    """Raised when ssh can't be found, or the remote command fails."""


def run(profile: str, command: Sequence[str], pty: bool = False) -> int:
    """Run ``command`` on ``profile``'s host, sharing this console.

    ``command`` is a sequence of logical argv tokens (like
    ``winsudo.run()``), quoted for the remote POSIX shell -- ssh itself
    only joins trailing args with plain spaces, it doesn't quote them.

    ``pty=True`` forces one (-tt): plain `ssh host -- command` doesn't
    allocate one (only interactive shell sessions get that by default),
    and `sudo` refuses to prompt for a password without one ("a terminal
    is required to read the password"). Only pass it for commands that
    actually invoke sudo -- forcing it unconditionally means every ssh
    session, even a silent read-only check, prints its own "Connection
    to <host> closed." on exit (a PTY-session-teardown message OpenSSH
    doesn't print for plain non-PTY commands), which reads as
    unexplained noise next to an unrelated step's own output.
    """
    ssh = find_ssh()
    if not ssh:
        raise RemoteExecError("ssh not found; install OpenSSH first")

    remote_command = " ".join(shlex.quote(arg) for arg in command)
    args = [ssh, *(["-tt"] if pty else []), profile, "--", remote_command]
    result = subprocess.run(args)
    return result.returncode


def capture(profile: str, command: Sequence[str]) -> str:
    """Like ``run()``, but returns the command's captured stdout instead
    of sharing this console -- for reading data back, not just acting.
    No PTY (would inject control chars into the captured text)."""
    ssh = find_ssh()
    if not ssh:
        raise RemoteExecError("ssh not found; install OpenSSH first")

    remote_command = " ".join(shlex.quote(arg) for arg in command)
    result = subprocess.run([ssh, profile, "--", remote_command], capture_output=True, text=True)
    if result.returncode != 0:
        raise RemoteExecError(
            f"Remote command failed with exit code {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout


def upload_bytes(profile: str, data: bytes, remote_path: str) -> None:
    """Write ``data`` to ``remote_path`` on ``profile``'s host. No scp
    dependency -- just pipes the bytes into a remote ``cat > file`` over
    the same ssh channel ``run()`` uses."""
    ssh = find_ssh()
    if not ssh:
        raise RemoteExecError("ssh not found; install OpenSSH first")

    remote_command = f"cat > {shlex.quote(remote_path)}"
    result = subprocess.run([ssh, profile, "--", remote_command], input=data)
    if result.returncode != 0:
        raise RemoteExecError(f"Upload failed with exit code {result.returncode}")


def upload(profile: str, local_path: Path, remote_path: str) -> None:
    """Copy a local file's bytes to ``remote_path`` on ``profile``'s host."""
    upload_bytes(profile, Path(local_path).read_bytes(), remote_path)
