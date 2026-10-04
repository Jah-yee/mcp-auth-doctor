"""A tiny MCP server plus authorization server on 127.0.0.1, standard library only.

Used to produce the example output in the README and handy for trying the tool without
a real server. `--broken` reproduces three real-world faults: a trailing-slash mismatch
in the protected resource metadata, no PKCE advertised, and a token endpoint that
answers errors as application/x-www-form-urlencoded.

    python scripts/demo_server.py [--port 8765] [--broken]
    mcp-auth-doctor http://127.0.0.1:8765/mcp
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

TOKEN = "demo-access-token"
CODE = "demo-code"


def make_handler(base: str, broken: bool):
    prm = {
        "resource": base + "/mcp/" if broken else base + "/mcp",
        "authorization_servers": [base],
        "scopes_supported": ["mcp:read"],
    }
    md = {
        "issuer": base,
        "authorization_endpoint": base + "/authorize",
        "token_endpoint": base + "/token",
        "registration_endpoint": base + "/register",
        "response_types_supported": ["code"],
        "client_id_metadata_document_supported": True,
        "authorization_response_iss_parameter_supported": True,
    }
    if not broken:
        md["code_challenge_methods_supported"] = ["S256"]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def send(
            self,
            status: int,
            body: bytes = b"",
            content_type: str = "application/json",
            **headers: str,
        ) -> None:
            self.send_response(status)
            if body:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key.replace("_", "-"), value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parts = urlsplit(self.path)
            if parts.path == "/.well-known/oauth-protected-resource/mcp":
                return self.send(200, json.dumps(prm).encode())
            if parts.path == "/.well-known/oauth-authorization-server":
                return self.send(200, json.dumps(md).encode())
            if parts.path == "/authorize":
                q = {k: v[0] for k, v in parse_qs(parts.query).items()}
                target = (
                    q["redirect_uri"]
                    + "?"
                    + urlencode({"code": CODE, "state": q.get("state", ""), "iss": base})
                )
                return self.send(302, Location=target)
            return self.send(404, b"not found", "text/plain")

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            path = urlsplit(self.path).path
            if path == "/mcp":
                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {TOKEN}":
                    prm_url = f"{base}/.well-known/oauth-protected-resource/mcp"
                    challenge = f'Bearer resource_metadata="{prm_url}", scope="mcp:read"'
                    return self.send(401, WWW_Authenticate=challenge)
                message = json.loads(raw or b"{}")
                if message.get("method") == "initialize":
                    result = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "result": {
                            "protocolVersion": "2026-07-28",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "demo", "version": "0"},
                        },
                    }
                    return self.send(
                        200, json.dumps(result).encode(), Mcp_Session_Id="demo-session"
                    )
                if message.get("method") == "tools/list":
                    result = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "result": {
                            "tools": [
                                {"name": "echo", "inputSchema": {"type": "object"}},
                                {"name": "time", "inputSchema": {"type": "object"}},
                            ]
                        },
                    }
                    return self.send(200, json.dumps(result).encode())
                return self.send(202)
            if path == "/register":
                client = json.loads(raw or b"{}")
                client["client_id"] = "demo-client"
                return self.send(201, json.dumps(client).encode())
            if path == "/token":
                data = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                if data.get("code") == CODE and data.get("code_verifier") and data.get("resource"):
                    return self.send(
                        200,
                        json.dumps(
                            {"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600}
                        ).encode(),
                    )
                if broken:
                    return self.send(
                        400,
                        b"error=invalid_grant&error_description=bad+code",
                        "application/x-www-form-urlencoded",
                    )
                return self.send(
                    400,
                    json.dumps(
                        {"error": "invalid_grant", "error_description": "bad code"}
                    ).encode(),
                )
            return self.send(404, b"not found", "text/plain")

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--broken", action="store_true")
    args = parser.parse_args()
    base = f"http://127.0.0.1:{args.port}"
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(base, args.broken))
    print(
        f"demo MCP server at {base}/mcp ({'broken' if args.broken else 'correct'})", file=sys.stderr
    )
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()


if __name__ == "__main__":
    main()
