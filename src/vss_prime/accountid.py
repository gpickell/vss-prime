"""Capture the VertiGIS Studio Account ID and stash it on the remote
host at /opt/vertigis-studio/account.txt.

Same flow as vertigis/host-kit's license-tool (Go): a local HTTP server
redirects the user's browser to VertiGIS's identity service; it comes
back via an OAuth form_post with `id`/`idUrl`, which we resolve to the
actual accountId. client_id/redirect_uri/port are registered with that
identity service, so they're copied verbatim, not generated locally.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import remote

PORT = 7780
AUTH_URL = (
    "https://identity.vertigisstudio.com/authorize"
    "?client_id=pTmBlZldlUaNrhFn"
    "&redirect_uri=http%3A%2F%2Flocalhost%3A7780%2Fa5510196-002b-4e2e-ba4e-8fdb91ee5287%2Fonline-activate"
    "&response_mode=form_post"
    "&activate=no_grant"
)
ACCOUNT_FILE = "/opt/vertigis-studio/account.txt"


def _resolve_account_id(fields: dict) -> "str | None":
    id_value = fields.get("id", [None])[0]
    id_url = fields.get("idUrl", [None])[0]
    if not id_value or not id_url:
        return None
    try:
        with urllib.request.urlopen(f"{id_url}?id={id_value}") as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError):
        return None
    account_id = data.get("accountId")
    return account_id or None


def _fetch_account_id() -> str:
    """Run the local callback server until the identity flow completes,
    returning the VertiGIS Account ID. Blocks until the user visits the
    link and completes the flow in their browser."""
    result: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # quiet -- no per-request noise
            pass

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", AUTH_URL)
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            account_id = _resolve_account_id(urllib.parse.parse_qs(body))
            self.send_response(200 if account_id else 404)
            self.end_headers()
            if account_id:
                result["account_id"] = account_id

    server = HTTPServer(("localhost", PORT), Handler)
    try:
        print(f"Please visit: http://localhost:{PORT}/")
        while "account_id" not in result:
            server.handle_request()
    finally:
        server.server_close()
    return result["account_id"]


def is_known(profile: str) -> bool:
    return remote.run(profile, ["test", "-s", ACCOUNT_FILE]) == 0


def ensure_account_id(profile: str) -> None:
    """Capture the Account ID (via the browser flow) and stash it
    remotely, unless it's already there."""
    if is_known(profile):
        return
    print(f"No Account ID stashed yet at {ACCOUNT_FILE} -- identifying via your browser now...")
    account_id = _fetch_account_id()
    remote.upload_bytes(profile, (account_id + "\n").encode("utf-8"), ACCOUNT_FILE)
    print(f"Account ID {account_id} saved to {ACCOUNT_FILE} on the remote host.")
