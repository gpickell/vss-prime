"""Entry point. No menu: each step runs automatically and flows into the
next, then the process quits. Command-line options are limited to
startup actions: ``--sudo`` warms up the elevation facility,
``--force-ssh-install`` reinstalls OpenSSH even if it's already present.
"""
from __future__ import annotations

import argparse
import sys
from typing import Optional

import questionary

from . import accountid, certenroll, provision, sshinstall, sshkey, sshprofile, trustscrape, winsudo

_INTRO = """\
vss-prime sets up and manages VertiGIS Studio materials on a remote
Linux host. Most of the steps below run unattended once you confirm
here -- only the certificate wizard and trust scrape ask again
individually. Unattended actions this run may take:

  - Install the Windows OpenSSH client (elevated), if missing.
  - Install gsudo via winget, if missing -- used for every local
    elevated action below.
  - Generate a new SSH ed25519 keypair in ~/.ssh, if you don't have one.
  - Create/update an SSH profile in ~/.ssh/config and copy your public
    key to the remote host's authorized_keys.
  - On the remote host: install packages (curl, acl) and Docker via
    the official `curl | sh` install script, add your user to the
    docker group, and set up /opt/vertigis-studio.
  - Create a shared settings folder under %ProgramData%\\vss-prime
    with ACL grants.

Certificate enrollment and the CA trust scrape will prompt you
individually before doing anything.\
"""


def _show_intro() -> bool:
    print(_INTRO)
    return bool(questionary.confirm("Proceed?", default=True).ask())


def _warmup_sudo() -> None:
    try:
        winsudo.ensure_sudo()
    except winsudo.ElevationError as exc:
        print(f"Elevation failed: {exc}")
        return
    print("Elevation OK.")


def _ensure_ssh(force: bool) -> None:
    try:
        ok = sshinstall.ensure_ssh(force=force)
    except (winsudo.ElevationError, RuntimeError) as exc:
        print(f"SSH install failed: {exc}")
        return
    print("SSH client OK." if ok else "SSH client still missing after install attempt.")


def _ensure_key() -> None:
    try:
        ok = sshkey.ensure_key()
    except RuntimeError as exc:
        print(f"SSH key setup failed: {exc}")
        return
    print("SSH key OK." if ok else "SSH key still missing after generation attempt.")


def _choose_ssh_profile() -> Optional[str]:
    try:
        profile = sshprofile.choose_profile()
    except RuntimeError as exc:
        print(f"SSH profile setup failed: {exc}")
        return None
    print(f"Using profile: {profile}" if profile else "Cancelled.")
    return profile


def _ensure_auto_logon(profile: Optional[str]) -> None:
    if not profile:
        return
    try:
        ok = sshprofile.ensure_auto_logon(profile)
    except RuntimeError as exc:
        print(f"Auto-logon setup failed: {exc}")
        return
    print("Auto-logon OK." if ok else "Auto-logon still not working after propagation attempt.")


def _provision(profile: Optional[str], force: bool) -> None:
    if not profile:
        return
    try:
        provision.provision(profile, force=force)
    except RuntimeError as exc:
        print(f"Provisioning failed: {exc}")
        return
    print("Provisioning OK.")


def _ensure_account_id(profile: Optional[str]) -> None:
    if not profile:
        return
    try:
        accountid.ensure_account_id(profile)
    except RuntimeError as exc:
        print(f"Account ID setup failed: {exc}")
        return
    print("Account ID OK.")


def _collect_certs(profile: Optional[str]) -> None:
    if not profile:
        return
    try:
        combos = certenroll.collect_combos(profile)
    except RuntimeError as exc:
        print(f"Certificate/SAN collection failed: {exc}")
        return
    san_count = sum(len(sans) for sans in combos.values())
    print(f"{len(combos)} certificate(s), {san_count} SAN(s) collected.")


def _enroll_certs(profile: Optional[str]) -> None:
    if not profile:
        return
    try:
        certenroll.enroll_loop(profile)
    except RuntimeError as exc:
        print(f"Certificate enrollment failed: {exc}")


def _check_certs(profile: Optional[str]) -> None:
    if not profile:
        return
    try:
        certenroll.check_loop(profile)
    except RuntimeError as exc:
        print(f"Certificate check failed: {exc}")


def _promote_certs(profile: Optional[str]) -> None:
    if not profile:
        return
    try:
        certenroll.promote_loop(profile)
    except RuntimeError as exc:
        print(f"Certificate promotion failed: {exc}")


def _scrape_trust(profile: Optional[str]) -> None:
    if not profile:
        return
    try:
        trustscrape.scrape_trust_anchors(profile)
    except RuntimeError as exc:
        print(f"CA trust scrape failed: {exc}")


def main() -> None:
    if sys.platform != "win32":
        print("vss-prime currently targets Windows hosts only.")
        return

    parser = argparse.ArgumentParser(prog="vss-prime")
    parser.add_argument(
        "--sudo",
        action="store_true",
        help="Warm up the sudo facility (prompt + probe) on start.",
    )
    parser.add_argument(
        "--force-ssh-install",
        action="store_true",
        help="Reinstall the OpenSSH client even if already present.",
    )
    parser.add_argument(
        "--force-provision",
        action="store_true",
        help="Redo all remote provisioning (Docker, /opt/vertigis-studio) even if already in place.",
    )
    args = parser.parse_args()

    if not _show_intro():
        print("Cancelled.")
        return

    if args.sudo:
        _warmup_sudo()

    _ensure_ssh(args.force_ssh_install)
    _ensure_key()
    profile = _choose_ssh_profile()
    _ensure_auto_logon(profile)
    _provision(profile, args.force_provision)
    _ensure_account_id(profile)
    _collect_certs(profile)
    _enroll_certs(profile)
    _check_certs(profile)
    _promote_certs(profile)
    _scrape_trust(profile)


if __name__ == "__main__":
    main()
