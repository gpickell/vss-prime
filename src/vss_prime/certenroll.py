"""Manual certificate enrollment wizard, as a 4-stage pipeline per CN:

  collecting (Loop 1: has SANs) -> pending (Loop 2: submitted, request
  ID stashed locally) -> staged (Loop 3: issued cert retrieved, kept
  locally) -> live (Loop 4: transferred + triaged into certs/live/).

The private key is generated remotely in Loop 2 and never leaves the
remote host; only the CSR (public) travels to Windows for submission,
and only the issued cert (also public) travels back. "Pending" and
"staged" state live locally (settings.SETTINGS_DIR), not on the remote
host -- Loop 4 is the only step that pushes staged material back out.

Resubmitting over an existing pending request is allowed, not gated --
this models the real process rather than hand-holding; it just orphans
the old request's key, which is the user's call to make.
"""
from __future__ import annotations

import importlib.resources
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import questionary

from . import remote, winsudo
from .settings import SETTINGS_DIR, ensure_scratch_dir, get_setting, set_setting

ENROLL_PATH = "/opt/vertigis-studio/certs/enroll"
LIVE_PATH = "/opt/vertigis-studio/certs/live"
_CN_SETTING_KEY = "cert_names"
_PENDING_SETTING_KEY = "cert_pending"

# Local (Windows-side) staging area: pending CSR copies and retrieved-
# but-not-yet-promoted certs. Never the private key -- that stays
# remote the whole time. Under settings.SETTINGS_DIR (shared,
# ACL'd %ProgramData%), not the user's own profile -- an elevated
# certreq doesn't necessarily run as this same user elevated, and a
# different admin account used for elevation typically has no access
# to another user's profile folder at all.
STAGING_DIR = SETTINGS_DIR / "certs"

CERT_TEMPLATE = "WebServerV3"
TRIAGE_SCRIPT_NAME = "vss-prime-triage.sh"

NEW_CERTIFICATE = "New certificate..."
NOT_NOW = "Not Now"
CLEAR = "Clear"

# Prints "CN\t<name>" before each enroll dir's SANs and "SAN\t<fqdn>"
# per non-empty line of its sans.txt -- a plain "cn:san one per line"
# transcript would be ambiguous to re-parse (blank lines, no SANs at
# all); the glob matching nothing in plain sh expands to the literal
# pattern, which `[ -d ... ]` then correctly skips.
_LIST_EXISTING_SCRIPT = f"""
for d in {ENROLL_PATH}/*/; do
    [ -d "$d" ] || continue
    cn=$(basename "$d")
    printf 'CN\\t%s\\n' "$cn"
    if [ -f "$d/sans.txt" ]; then
        while IFS= read -r san; do
            [ -n "$san" ] && printf 'SAN\\t%s\\n' "$san"
        done < "$d/sans.txt"
    fi
done
""".strip()


def _existing_combos(profile: str) -> Dict[str, List[str]]:
    """CN -> SANs already present under certs/enroll on the remote host."""
    output = remote.capture(profile, ["sh", "-c", _LIST_EXISTING_SCRIPT])

    combos: Dict[str, List[str]] = {}
    current_cn: Optional[str] = None
    for line in output.splitlines():
        if line.startswith("CN\t"):
            current_cn = line[3:]
            combos.setdefault(current_cn, [])
        elif line.startswith("SAN\t") and current_cn:
            combos[current_cn].append(line[4:])
    return combos


def _remember_cn(name: str) -> None:
    names = get_setting(_CN_SETTING_KEY, [])
    if name not in names:
        names.append(name)
        set_setting(_CN_SETTING_KEY, names)


def _cn_suggestions(existing: Dict[str, List[str]]) -> List[str]:
    """Local settings first, then any remotely-enrolled CN not already
    in that list (e.g. enrolled from a different client machine)."""
    names = list(get_setting(_CN_SETTING_KEY, []))
    for name in existing:
        if name not in names:
            names.append(name)
    return names


def _print_combos(combos: Dict[str, List[str]]) -> None:
    print("Certificates and SANs configured so far (CN: SAN):")
    if not any(combos.values()):
        print("  (none yet)")
        return
    for cn, sans in combos.items():
        for san in sans:
            print(f"  {cn}: {san}")


def _persist_sans(profile: str, cn: str, sans: List[str]) -> None:
    """Write certs/enroll/<cn>/sans.txt immediately -- so an added SAN
    is actually durable right away, not just in-memory until (if ever)
    Loop 2 runs. No sudo needed: the dir's group-write + default ACL
    (set up in provision.sh) already let this ssh user write there."""
    cn_dir = f"{ENROLL_PATH}/{cn}"
    exit_code = remote.run(profile, ["mkdir", "-p", cn_dir])
    if exit_code != 0:
        raise RuntimeError(f"Creating {cn_dir} failed with exit code {exit_code}")

    content = "".join(f"{san}\n" for san in sans)
    remote.upload_bytes(profile, content.encode("utf-8"), f"{cn_dir}/sans.txt")


def _ask_cn(suggestions: List[str]) -> Optional[str]:
    if not suggestions:
        return questionary.text("Certificate:").ask()

    choice = questionary.select("Certificate:", choices=[*suggestions, NEW_CERTIFICATE]).ask()
    if choice is None or choice != NEW_CERTIFICATE:
        return choice
    return questionary.text("Certificate:").ask()


def collect_combos(profile: str) -> Dict[str, List[str]]:
    """Loop 1: interactively add (CN, SAN) pairs, reviewed against
    everything already enrolled remotely too. Returns the combined set
    (existing + newly added); doing anything with it (Loop 2) is
    deferred."""
    combos = _existing_combos(profile)

    while True:
        _print_combos(combos)
        if not questionary.confirm("Add another Certificate/SAN?").ask():
            break

        name = _ask_cn(_cn_suggestions(combos))
        if not name:
            continue

        san = questionary.text("SAN (FQDN):").ask()
        if not san:
            continue

        _remember_cn(name)
        sans = combos.setdefault(name, [])
        if san not in sans:
            sans.append(san)
            _persist_sans(profile, name, sans)
            print(f"{name}: {san} saved to the remote host (certs/enroll/{name}/sans.txt).")

    return combos


# --- shared: certreq output files ---------------------------------------


def _staged_paths(cn: str) -> Tuple[Path, Path, Path]:
    """(CertFileOut, CertChainFileOut, FullResponseFileOut) for cn, under
    STAGING_DIR -- the 2nd/3rd/4th positional output args certreq
    -submit/-retrieve both accept. Asking for the chain directly (a
    proper PKCS7 bundle) means triage.sh doesn't have to guess whether
    CertFileOut happens to contain one too.

    Appends suffixes to the full filename rather than using
    Path.with_suffix(), which would instead replace cn's own trailing
    ".tld" (cn is a FQDN, e.g. "example.com" -> with_suffix(".cer")
    wrongly gives "example.cer", losing ".com" entirely)."""
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    base = STAGING_DIR / cn
    return (
        base.with_name(base.name + ".cer"),
        base.with_name(base.name + ".p7b"),
        base.with_name(base.name + ".rsp"),
    )


def _staged_chain_path(cn: str) -> Path:
    return _staged_paths(cn)[1]


def _is_valid_cert_file(path: Path) -> bool:
    """Cheap, local-only sniff: does this file actually hold a staged
    cert, not just an empty/stale placeholder? No local openssl
    assumed -- that's only ever run remotely (triage.sh); a plain
    substring check is enough to tell "certreq actually wrote a result
    here" apart from "nothing's there yet". Windows labels PKCS7
    bundles with the same generic "CERTIFICATE" PEM header as a plain
    cert (confirmed against a real .p7b), so this works for both
    _staged_cert_path and _staged_chain_path."""
    return path.exists() and "BEGIN CERTIFICATE" in path.read_text(
        encoding="utf-8", errors="ignore"
    )


def _read_response_excerpt(response_path: Path) -> str:
    """Best-effort: FullResponseFileOut is a PKCS7/CMS blob, but CAs
    often embed a plain-text error string directly inside it (e.g. the
    "Error verifying access" we found in a real one) -- pull out
    printable runs rather than trying to parse the ASN.1 properly."""
    if not response_path.exists():
        return ""
    data = response_path.read_bytes()
    matches = re.findall(rb"[ -~]{8,}", data)
    return " / ".join(m.decode("ascii") for m in matches[-3:])


# --- Loop 2: submit ---------------------------------------------------


def _pending() -> Dict[str, Dict[str, str]]:
    """cn -> {request_id, ca_name, ca_config}. The CA has to be
    remembered per pending item, not re-asked/re-guessed later --
    checking a request needs the same CA it was submitted to.

    Self-heals two ways, driven by what's actually sitting on disk
    rather than trusting our own bookkeeping to always have cleared
    things correctly:
    - old-format entries (a bare request-id string, from before the CA
      was remembered alongside it): can't be retrieved anyway (no CA
      recorded), so dropped -- the CN just becomes eligible for Loop 2
      again.
    - already-resolved entries (a valid .p7b is already staged for
      that CN): nothing left to check -- certreq rejects a -retrieve
      for a request that's already been fully issued, so these must
      not be offered in Loop 3 regardless of how they got left
      pending (a crash between retrieve succeeding and this entry
      being cleared, manual file changes, etc.)."""
    pending = get_setting(_PENDING_SETTING_KEY, {})
    cleaned = {
        cn: entry
        for cn, entry in pending.items()
        if isinstance(entry, dict) and not _is_valid_cert_file(_staged_chain_path(cn))
    }
    if cleaned != pending:
        set_setting(_PENDING_SETTING_KEY, cleaned)
    return cleaned


def _set_pending(cn: str, request_id: str, ca_name: str, ca_config: str) -> None:
    pending = _pending()
    pending[cn] = {"request_id": request_id, "ca_name": ca_name, "ca_config": ca_config}
    set_setting(_PENDING_SETTING_KEY, pending)


def _clear_pending(cn: str) -> None:
    pending = _pending()
    pending.pop(cn, None)
    set_setting(_PENDING_SETTING_KEY, pending)


def _generate_csr(profile: str, cn: str, sans: List[str]) -> None:
    """(Re)generate cert.csr/privkey.pem remotely from the CN's current
    SAN list. Always fresh, never reused: an old CSR could be missing
    SANs added since it was created, and a stale key paired with a
    pending request is a hazard, not a feature."""
    cn_dir = f"{ENROLL_PATH}/{cn}"
    san_ext = "subjectAltName=" + ",".join(f"DNS:{san}" for san in sans)
    exit_code = remote.run(
        profile,
        [
            "openssl", "req", "-new", "-newkey", "rsa:4096", "-nodes",
            "-keyout", f"{cn_dir}/privkey.pem",
            "-out", f"{cn_dir}/cert.csr",
            "-subj", f"/CN={cn}",
            "-addext", san_ext,
        ],
    )
    if exit_code != 0:
        raise RuntimeError(f"CSR generation for {cn!r} failed with exit code {exit_code}")


def _dump_value(line: str) -> str:
    """Extract the quoted value after the first ':' in a certutil
    -dump field line, e.g. '  Config:   "server\\ca"' -> 'server\\ca'."""
    _, _, rest = line.partition(":")
    rest = rest.strip()
    if rest.startswith('"') and rest.endswith('"') and len(rest) >= 2:
        return rest[1:-1]
    return rest


def list_cas() -> List[Tuple[str, str]]:
    """(Name, Config) for every CA certutil -dump can see -- run
    elevated (gsudo), since that's the context the actual certreq
    submission runs in too, not just the interactive user's."""
    _, output = winsudo.capture(["certutil", "-dump"])

    cas: List[Tuple[str, str]] = []
    name: Optional[str] = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Name:"):
            name = _dump_value(line)
        elif line.startswith("Config:") and name is not None:
            cas.append((name, _dump_value(line)))
            name = None
    return cas


def _submit_csr(cn: str, csr_path: Path, ca_config: str) -> Tuple[str, bool]:
    """Submit a CSR via certreq (admin/machine context) to the given CA
    (its "Config" string, e.g. "server\\caname" -- see list_cas()).

    Returns (request_id, issued_immediately). On synchronous issuance
    (no approval needed -- e.g. auto-issuing templates), the CA hands
    the real cert straight back in the output file at submit time; a
    later -retrieve by Request ID then has nothing left to retrieve and
    the CA rejects it (confirmed: an "Error verifying access" PKCS7
    response for a request whose .cer already held a real issued
    cert). So this result matters -- the caller must *not* treat an
    immediately-issued cert as merely "submitted, check later"."""
    cer_path, chain_path, response_path = _staged_paths(cn)
    # Clear any lingering output files from a prior submission for this
    # CN (harmless either way -- its key was already replaced by
    # _generate_csr) -- but the actual overwrite-confirmation prompt
    # certreq shows is unrelated to these files: it's certreq noticing
    # what it considers a duplicate/conflicting existing cert or
    # request for the same subject, tracked in the CA/local machine
    # state, not on disk. -f/-q are the documented way to force past
    # that (and any other interactive dialog) without prompting;
    # nothing here reads stdin to answer one.
    for path in (cer_path, chain_path, response_path):
        path.unlink(missing_ok=True)
    exit_code, output = winsudo.capture(
        [
            "certreq", "-submit", "-f", "-q", "-adminforcemachine", "-config", ca_config,
            "-attrib", f"CertificateTemplate:{CERT_TEMPLATE}",
            str(csr_path), str(cer_path), str(chain_path), str(response_path),
        ]
    )
    match = re.search(r'RequestId:\s*"?(\d+)"?', output, re.IGNORECASE)
    if not match:
        excerpt = _read_response_excerpt(response_path)
        detail = f"\n{excerpt}" if excerpt else ""
        raise RuntimeError(
            f"Could not find a Request ID in certreq output (exit {exit_code}):\n{output}{detail}"
        )
    return match.group(1), _is_valid_cert_file(cer_path)


def _enrollable_cns(combos: Dict[str, List[str]]) -> List[str]:
    """CNs with at least one SAN -- the only ones worth submitting."""
    return [cn for cn, sans in combos.items() if sans]


def enroll_loop(profile: str) -> None:
    """Loop 2: submit a fresh enrollment request for a chosen CN.
    Skipped if there's nothing with any SANs yet."""
    combos = _existing_combos(profile)
    candidates = _enrollable_cns(combos)
    if not candidates:
        return

    pending = _pending()
    for cn in candidates:
        if cn in pending:
            print(
                f"{cn}: already has a pending request (ID {pending[cn]['request_id']} via "
                f"{pending[cn]['ca_name']}) -- enrolling again replaces its CSR/key, "
                "orphaning that request."
            )

    cn = questionary.select(
        "Submit an enrollment request for which certificate?",
        choices=[*candidates, NOT_NOW],
        default=NOT_NOW,
    ).ask()
    if cn is None or cn == NOT_NOW:
        return

    print("Checking available Certificate Authorities (certutil -dump, elevated -- may prompt)...")
    cas = list_cas()
    if not cas:
        raise RuntimeError("No certificate authorities visible (certutil -dump found none)")

    ca_choice = questionary.select(
        f"Enroll {cn} now via which CA?",
        choices=[*(name for name, _config in cas), NOT_NOW],
        default=NOT_NOW,
    ).ask()
    if ca_choice is None or ca_choice == NOT_NOW:
        return
    ca_config = next(config for name, config in cas if name == ca_choice)

    print(f"Generating a new private key + CSR for {cn} on the remote host (key stays there)...")
    _generate_csr(profile, cn, combos[cn])
    csr_text = remote.capture(profile, ["cat", f"{ENROLL_PATH}/{cn}/cert.csr"])

    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    csr_path = STAGING_DIR / f"{cn}.csr"
    csr_path.write_text(csr_text, encoding="utf-8", newline="\n")

    print(f"Submitting the CSR to {ca_choice} via certreq (elevated -- may prompt)...")
    request_id, issued_immediately = _submit_csr(cn, csr_path, ca_config)
    if issued_immediately:
        # Nothing to retrieve later -- the cert's already sitting at
        # _staged_cert_path(cn) (same path _submit_csr just wrote to).
        # Must not also mark this pending: a later -retrieve for an
        # already-completed request is what the CA rejects.
        print(f"{cn}: issued immediately by {ca_choice} (synchronous CA) -- staged locally, ready to promote.")
    else:
        _set_pending(cn, request_id, ca_choice, ca_config)
        print(f"{cn}: submitted to {ca_choice} (Request ID {request_id}). Use the check step later to retrieve it.")


# --- Loop 3: check -----------------------------------------------------


def _staged_cert_path(cn: str) -> Path:
    return _staged_paths(cn)[0]


def check_loop(profile: str) -> None:
    """Loop 3: picking a CN directly checks its pending request (no
    separate yes/no step -- picking it is the confirmation, same as
    Loop 2's CA picker). Works the same whether the CA auto-issued or
    took a while -- one retrieval path, not two. "Clear" abandons *all*
    pending requests at once, not just one. Skipped if nothing's
    pending."""
    pending = _pending()
    candidates = list(pending)
    if not candidates:
        return

    choice = questionary.select(
        "Check the pending enrollment for which certificate?",
        choices=[*candidates, NOT_NOW, CLEAR],
        default=NOT_NOW,
    ).ask()
    if choice is None or choice == NOT_NOW:
        return
    if choice == CLEAR:
        for cn in candidates:
            _clear_pending(cn)
        print(f"Cleared {len(candidates)} pending request(s).")
        return

    cn = choice
    entry = pending[cn]
    request_id = entry["request_id"]
    ca_config = entry["ca_config"]
    issued_path, chain_path, response_path = _staged_paths(cn)
    print(
        f"Checking Request ID {request_id} with {entry['ca_name']} "
        "(certreq -retrieve, elevated -- may prompt)..."
    )
    # Clear any lingering output files from a prior check of this CN --
    # same reasoning as _submit_csr: avoids an overwrite prompt nothing
    # here reads stdin to answer.
    for path in (issued_path, chain_path, response_path):
        path.unlink(missing_ok=True)
    exit_code, output = winsudo.capture(
        [
            "certreq", "-retrieve", "-f", "-q", "-config", ca_config, request_id,
            str(issued_path), str(chain_path), str(response_path),
        ]
    )
    if exit_code != 0 or not issued_path.exists():
        excerpt = _read_response_excerpt(response_path)
        detail = f" ({excerpt})" if excerpt else ""
        print(f"{cn}: still pending (Request ID {request_id}){detail}; the CA hasn't issued it yet.")
        return

    _clear_pending(cn)
    print(f"{cn}: issued! Staged locally at {issued_path}; use the promote step to push it live.")


# --- Loop 4: promote ----------------------------------------------------


def _staged_cns() -> List[str]:
    """CNs ready to promote -- driven by a valid .p7b (CertChainFileOut)
    sitting in STAGING_DIR, not .cer: in practice (confirmed against
    real retrieved/issued data) the CA always writes both together
    whenever something's actually been issued, and the chain is the
    more complete result, so its presence alone is the signal."""
    if not STAGING_DIR.exists():
        return []
    return [p.stem for p in STAGING_DIR.glob("*.p7b") if _is_valid_cert_file(p)]


def _triage_script_bytes() -> bytes:
    return importlib.resources.files(__package__).joinpath("triage.sh").read_bytes()


def _promote(profile: str, cn: str) -> None:
    staged, chain, _response = _staged_paths(cn)
    remote.upload(profile, staged, f"{ENROLL_PATH}/{cn}/issued.cer")
    # The chain (CertChainFileOut) may not exist for older staged data,
    # or if the CA/template doesn't produce one -- triage.sh falls back
    # to guessing from issued.cer alone when it's missing.
    if chain.exists():
        remote.upload(profile, chain, f"{ENROLL_PATH}/{cn}/issued.p7b")
    remote.upload_bytes(profile, _triage_script_bytes(), TRIAGE_SCRIPT_NAME)

    exit_code = remote.run(profile, ["sh", TRIAGE_SCRIPT_NAME, cn])
    if exit_code != 0:
        raise RuntimeError(f"Promoting {cn!r} to live failed with exit code {exit_code}")

    staged.unlink(missing_ok=True)
    chain.unlink(missing_ok=True)


def promote_loop(profile: str) -> None:
    """Loop 4: picking a CN directly promotes it (no separate yes/no
    step -- picking it is the confirmation, same as Loop 2's CA
    picker), transferring its locally-staged cert to the remote host
    and triaging it into certs/live/<cn>/, paired with the privkey.pem
    that's been remote the whole time. "Clear" discards *all* staged
    certs at once, not just one, without promoting them. Skipped if
    nothing's staged."""
    candidates = _staged_cns()
    if not candidates:
        return

    choice = questionary.select(
        "Promote the staged (issued) cert to live for which certificate?",
        choices=[*candidates, NOT_NOW, CLEAR],
        default=NOT_NOW,
    ).ask()
    if choice is None or choice == NOT_NOW:
        return
    if choice == CLEAR:
        for cn in candidates:
            for path in _staged_paths(cn):
                path.unlink(missing_ok=True)
        print(f"Cleared {len(candidates)} staged cert(s) (discarded, not promoted).")
        return

    cn = choice
    print(
        f"Transferring the issued cert for {cn} to the remote host and building "
        f"{LIVE_PATH}/{cn}/ (cert.pem/chain.pem/fullchain.pem, paired with its privkey.pem)..."
    )
    _promote(profile, cn)
    print(f"{cn}: live at {LIVE_PATH}/{cn}/ on the remote host.")
