"""Scrape this Windows machine's effective TLS trust anchors -- public
root CAs and any enterprise/domain CAs pushed via policy alike, exactly
what Windows itself would use to validate a server's chain -- into
/opt/vertigis-studio/certs/trust, shaped like /etc/ssl/certs: real PEM
files plus OpenSSL subject-hash symlinks, all local to that one folder
so it works standalone once bind-mounted into a container (unlike a
real /etc/ssl/certs, which often symlinks out elsewhere on the host).
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import ssl
import subprocess
import tarfile
from typing import Dict, List, Tuple

import questionary

from . import remote

TRUST_PATH = "/opt/vertigis-studio/certs/trust"
TRUST_BUNDLE_NAME = "ca-certificates.crt"

# TLS Server Authentication EKU OID -- a cert's own store-trust property
# (not its embedded extensions) is what decides whether Windows would
# actually use it to validate a TLS server's chain; certs restricted to
# other purposes only (code signing, email, timestamping...) aren't
# anchors for our purpose even if they're otherwise valid CAs.
_SERVER_AUTH_EKU = "1.3.6.1.5.5.7.3.1"

_HASH_PREFIX_LEN = 8


def _kebab(subject: str) -> str:
    """Strict collapse for a filesystem-safe, human-scannable name: any
    run of characters other than A-Z/0-9 (case-insensitive) becomes a
    single '-'. Uppercased throughout -- meant to be skimmed in a
    directory listing, not round-tripped back into a real subject."""
    collapsed = re.sub(r"[^A-Za-z0-9]+", "-", subject).upper()
    return collapsed.strip("-")


def _filename(der: bytes, subject: str) -> str:
    """<hash-prefix>-<KEBAB-SUBJECT>.pem. The hash (over the DER, i.e. a
    real fingerprint) is what actually guarantees uniqueness -- CA
    rollovers share a subject across distinct certs (confirmed for
    real: this environment's own issuing CA has 4 generations under one
    CN), so the kebab portion alone can and does collide."""
    digest = hashlib.sha256(der).hexdigest()[:_HASH_PREFIX_LEN].upper()
    return f"{digest}-{_kebab(subject)}.pem"


def _root_store_metadata() -> Dict[str, Dict[str, object]]:
    """sha1-hex (uppercase, matching a cert's Thumbprint/fingerprint
    convention) -> {"subject": str, "can_sign": bool}, for every cert in
    the Root store. ssl.enum_certificates() exposes the raw cert bytes
    directly (no subprocess needed for that part), but not parsed
    subject/extension data -- PowerShell's Cert: provider is the
    simplest source for that without hand-rolling an ASN.1 parser.

    can_sign is True unless the cert carries its own Key Usage
    extension that excludes Certificate Signing -- confirmed necessary
    for real: two self-signed, non-CA leaf certs (this machine's own
    WinRM-style service certs) turned up in the Root store and are
    trusted for TLS server auth just like a real CA would be (that
    trust is a separate, Windows-applied property, not tied to being a
    CA), but their own Key Usage is Key/Data Encipherment only -- no
    Certificate Signing bit, so they can't actually sign anything.
    Several genuine (if ancient) root CAs have no Key Usage extension
    at all; can_sign defaults to True for those since there's nothing
    in the cert itself to rule them out.

    self_signed (Subject == Issuer) is the third leg: confirmed for
    real that a handful of entries in this store are genuine, fully-
    formed CAs (CA:true, real signing Key Usage, trusted for server
    auth) that still aren't roots -- an enterprise/vendor issuing CA
    published into Root non-standardly, or a legitimate cross-signed
    "bridge" root sharing a subject with its self-signed counterpart.
    Keeping only the self-signed copy is what actually fixes a real
    found bug: a stale/expired generation of one such intermediate was
    otherwise shipping as a trust anchor."""
    script = (
        "Get-ChildItem Cert:\\LocalMachine\\Root | ForEach-Object { "
        "$ku = $_.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Key Usage' }; "
        "$canSign = -not $ku -or [bool]($ku.KeyUsages -band "
        "[Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign); "
        "[PSCustomObject]@{ Thumbprint = $_.Thumbprint; Subject = $_.Subject; "
        "SelfSigned = ($_.Subject -eq $_.Issuer); CanSign = $canSign } "
        "} | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Reading Root store metadata failed: {result.stderr.strip()}")

    entries = json.loads(result.stdout)
    if isinstance(entries, dict):
        entries = [entries]
    return {
        entry["Thumbprint"].upper(): {
            "subject": entry["Subject"],
            "can_sign": entry["CanSign"],
            "self_signed": entry["SelfSigned"],
        }
        for entry in entries
    }


def _trust_anchors() -> List[Tuple[bytes, str]]:
    """(DER bytes, Subject) for every cert in the Root store that is
    self-signed, is actually capable of signing certs, AND that Windows
    itself trusts for TLS server authentication -- the direct
    equivalent of what populates a Linux ca-certificates bundle (public
    roots + enterprise/domain CAs pushed via policy), not "every cert
    this machine happens to trust for anything". Deduped by SHA-1 (the
    store can enumerate the same cert more than once)."""
    metadata = _root_store_metadata()
    seen: Dict[str, bytes] = {}
    for der, _encoding, trust in ssl.enum_certificates("ROOT"):
        if trust is not True and _SERVER_AUTH_EKU not in trust:
            continue
        sha1 = hashlib.sha1(der).hexdigest().upper()
        entry = metadata.get(sha1, {"can_sign": True, "self_signed": True})
        if not entry["can_sign"] or not entry["self_signed"]:
            continue
        seen.setdefault(sha1, der)
    return [(der, metadata[sha1]["subject"] if sha1 in metadata else sha1) for sha1, der in seen.items()]


def _linux_trust_anchors(profile: str) -> List[Tuple[bytes, str]]:
    """(DER bytes, Subject) for every cert already in the remote host's
    own /etc/ssl/certs -- merged in alongside the Windows-sourced
    anchors (not just overwritten) so a CA the sysadmin adds directly
    on the Linux side (their own update-ca-certificates, independent of
    this tool) survives our wipe-and-rebuild instead of getting
    silently dropped. Already curated upstream (confirmed for real:
    Debian's ca-certificates package is a dated snapshot of Mozilla's
    root list, 100% self-signed, no purpose-restricted entries) -- no
    extra filtering needed here, unlike the Windows side."""
    transcript = remote.capture(
        profile,
        ["sh", "-c", 'for f in /etc/ssl/certs/*.pem; do echo ===FILE===; openssl x509 -in "$f" -noout -subject; cat "$f"; done'],
    )
    anchors: List[Tuple[bytes, str]] = []
    for chunk in transcript.split("===FILE===\n")[1:]:
        subject_line, _, pem_block = chunk.partition("\n")
        subject = subject_line.removeprefix("subject=").strip()
        match = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem_block, re.DOTALL)
        if not match:
            continue
        der = base64.b64decode(match.group(1))
        anchors.append((der, subject))
    return anchors


def _to_pem(der: bytes) -> bytes:
    body = base64.encodebytes(der).decode("ascii")
    return f"-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n".encode("ascii")


def _build_tar(anchors: List[Tuple[bytes, str]]) -> bytes:
    """Pack every anchor's PEM bytes into one in-memory tar, named with
    the same _filename() each anchor would otherwise be uploaded under
    individually. One upload instead of one-SSH-connection-per-anchor
    (164 anchors meant 164 separate SSH handshakes -- confirmed slow in
    practice, with no progress output in between to show it was still
    working, not actually stalled)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for der, subject in anchors:
            pem = _to_pem(der)
            info = tarfile.TarInfo(name=_filename(der, subject))
            info.size = len(pem)
            tar.addfile(info, io.BytesIO(pem))
    return buf.getvalue()


def scrape_trust_anchors(profile: str) -> None:
    """PLAN.md Step: Scrape CA Material. Unions this machine's Windows
    trust anchors with whatever's already in the remote host's own
    /etc/ssl/certs (deduped by fingerprint through the same marshaling
    path, so both sources end up named/shaped identically) before
    wiping and rebuilding TRUST_PATH -- the Linux side is included so a
    CA the sysadmin added there directly survives the rebuild instead
    of being silently discarded just because this tool didn't source
    it. Then builds the subject-hash symlinks via `openssl rehash` --
    it only adds symlinks for what's already there, so the wipe has to
    happen before the fresh PEM files are uploaded, not after. Also
    builds a single concatenated TRUST_BUNDLE_NAME -- real /etc/ssl/certs
    keeps both representations in sync (the per-file/symlink directory
    for CApath-style consumers, a single bundle file for SSL_CERT_FILE-
    style ones like curl --cacert or Python's certifi/requests), and
    only one of the two was built here before. Built *after* rehash, not
    before: rehash's own file-extension scan would otherwise also pick
    up the bundle itself and hash it as if it were one more cert."""
    print(
        "Build the remote trust bundle, pulling CA trust anchors from:\n"
        "  - This machine's Windows Root store (public + enterprise CAs)\n"
        "  - The remote host's own /etc/ssl/certs"
    )
    proceed = questionary.confirm("Proceed?", default=True).ask()
    if not proceed:
        return

    print("Reading the Windows Root certificate store (no elevation needed)...")
    windows_anchors = _trust_anchors()
    print(f"{len(windows_anchors)} anchor(s) from Windows.")

    print(f"Reading the remote host's own /etc/ssl/certs (may already have sysadmin-added CAs)...")
    linux_anchors = _linux_trust_anchors(profile)
    print(f"{len(linux_anchors)} anchor(s) from the remote host.")

    merged: Dict[str, Tuple[bytes, str]] = {}
    for der, subject in (*windows_anchors, *linux_anchors):
        merged.setdefault(hashlib.sha256(der).hexdigest(), (der, subject))
    anchors = list(merged.values())
    print(f"{len(anchors)} unique trust anchor(s) after merge; transferring to {TRUST_PATH}...")

    remote.run(profile, ["rm", "-rf", TRUST_PATH])
    remote.run(profile, ["mkdir", "-p", TRUST_PATH])
    tar_path = f"{TRUST_PATH}.tar"
    remote.upload_bytes(profile, _build_tar(anchors), tar_path)
    exit_code = remote.run(profile, ["tar", "-xf", tar_path, "-C", TRUST_PATH])
    remote.run(profile, ["rm", "-f", tar_path])
    if exit_code != 0:
        raise RuntimeError(f"Extracting trust anchors failed with exit code {exit_code}")

    print("Building subject-hash symlinks (openssl rehash, local to the folder)...")
    exit_code = remote.run(profile, ["openssl", "rehash", TRUST_PATH])
    if exit_code != 0:
        raise RuntimeError(f"openssl rehash failed with exit code {exit_code}")

    print(f"Building the concatenated {TRUST_BUNDLE_NAME} bundle...")
    exit_code = remote.run(
        profile, ["sh", "-c", f"cat {TRUST_PATH}/*.pem > {TRUST_PATH}/{TRUST_BUNDLE_NAME}"]
    )
    if exit_code != 0:
        raise RuntimeError(f"Building {TRUST_BUNDLE_NAME} failed with exit code {exit_code}")

    print(f"{len(anchors)} trust anchor(s) live at {TRUST_PATH} on the remote host.")
