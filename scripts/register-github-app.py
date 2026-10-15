#!/usr/bin/env python3
"""Register an organization-owned test App through GitHub's browser manifest flow.

Credentials are written only to a new private directory. No OAuth or personal
access token is used, and no credentials or callback query strings are logged.
"""
import argparse
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen


def manifest(organization, repository, name, webhook, callback):
    return {
        "name": name,
        "url": f"https://github.com/{organization}/{repository}",
        "description": "Hermit Android signing integration test; test keys only.",
        "public": False,
        "hook_attributes": {"url": webhook, "active": True},
        "redirect_url": callback,
        "default_permissions": {
            "actions": "read", "attestations": "read", "contents": "write",
        },
        "default_events": ["workflow_run"],
        "request_oauth_on_install": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization", default="connectbot")
    parser.add_argument("--repository", default="test-signer-1")
    parser.add_argument("--name", default="ConnectBot Android Signer Test 1")
    parser.add_argument("--webhook", default="https://signer.their.net/webhooks/github")
    parser.add_argument("--port", type=int, default=18765)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    for identifier in (args.organization, args.repository):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", identifier):
            parser.error("Invalid organization/repository")
    if urlsplit(args.webhook).scheme != "https":
        parser.error("Webhook must use HTTPS")
    os.umask(0o077)
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    state = secrets.token_urlsafe(32)
    origin = f"http://127.0.0.1:{args.port}"
    app_manifest = manifest(args.organization, args.repository, args.name,
                            args.webhook, origin + "/callback")
    (args.out / "manifest.json").write_text(json.dumps(app_manifest, indent=2) + "\n")
    completed = False

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; form-action https://github.com; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            nonlocal completed
            if self.headers.get("Host") != f"127.0.0.1:{args.port}":
                return self.reply(403, "Invalid host")
            url = urlsplit(self.path)
            query = parse_qs(url.query, strict_parsing=False)
            values = query.get("state", [])
            if len(values) != 1 or not hmac.compare_digest(values[0], state):
                return self.reply(403, "Invalid registration state")
            if url.path == "/register":
                action = (f"https://github.com/organizations/{args.organization}"
                          f"/settings/apps/new?state={quote(state)}")
                return self.reply(200, '<!doctype html><title>Register test signer</title>'
                    '<h1>Register the ConnectBot test signer</h1>'
                    '<p>Permissions: Actions/read, attestations/read, contents/write. '
                    'Receives workflow_run events. Install on test-signer-1 only.</p>'
                    f'<form method="post" action="{html.escape(action, quote=True)}">'
                    f'<input type="hidden" name="manifest" value="{html.escape(json.dumps(app_manifest), quote=True)}">'
                    '<button type="submit">Continue to GitHub</button></form>')
            if url.path != "/callback" or completed:
                return self.reply(404, "Not found")
            codes = query.get("code", [])
            if len(codes) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", codes[0]):
                return self.reply(400, "Invalid callback code")
            try:
                request = Request("https://api.github.com/app-manifests/" + codes[0] + "/conversions",
                    data=b"", method="POST", headers={"Accept": "application/vnd.github+json",
                    "User-Agent": "android-signer-test-provisioning", "X-GitHub-Api-Version": "2022-11-28"})
                with urlopen(request, timeout=30) as response:
                    raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError("Oversized GitHub response")
                app = json.loads(raw)
                if (app["owner"]["login"].lower() != args.organization.lower()
                        or app["permissions"] != {**app_manifest["default_permissions"], "metadata": "read"}
                        or app["events"] != ["workflow_run"]):
                    raise ValueError("Unexpected App owner or permissions")
                for name, value in (("github-app.pem", app["pem"]),
                                    ("webhook-secret", app["webhook_secret"])):
                    with (args.out / name).open("x") as file:
                        file.write(value)
                public = {key: app[key] for key in ("id", "slug", "html_url", "owner", "permissions", "events")}
                with (args.out / "registration.json").open("x") as file:
                    file.write(json.dumps(public, indent=2) + "\n")
                completed = True
                install = "https://github.com/apps/" + quote(app["slug"], safe="") + "/installations/new"
                self.reply(200, '<!doctype html><title>Test signer registered</title>'
                    '<h1>App registered</h1><p>Credentials saved locally.</p>'
                    f'<p><a href="{html.escape(install, quote=True)}">Install on ConnectBot</a>; '
                    'select only test-signer-1.</p>')
                print("App registered:", app["slug"], "ID:", app["id"], flush=True)
                print("Install:", install, flush=True)
            except Exception:
                self.reply(502, "Registration could not be saved. Check the local credentials directory before retrying.")
                print("Registration failed; no callback or credential values logged.", flush=True)

    server = HTTPServer(("127.0.0.1", args.port), Handler)
    server.timeout = 1
    print(origin + "/register?state=" + state, flush=True)
    deadline = time.monotonic() + 3600
    try:
        while not completed and time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    if not completed:
        raise SystemExit("Registration expired; start a new session")


if __name__ == "__main__":
    main()
