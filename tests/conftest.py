"""respx-mocked MCP server and authorization server used by the check tests.

`mount(router, ...)` installs routes for one MCP server and one or more authorization
servers; every keyword has a correct default so a test only states what is broken.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx

MCP = "https://mcp.example.com/mcp"
AS = "https://auth.example.com"
PRM_PATH = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
PRM_ROOT = "https://mcp.example.com/.well-known/oauth-protected-resource"


@pytest.fixture
def router():
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as r:
        yield r


def as_metadata(issuer: str = AS, **overrides: Any) -> dict[str, Any]:
    md: dict[str, Any] = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "registration_endpoint": f"{issuer}/register",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "client_id_metadata_document_supported": True,
        "authorization_response_iss_parameter_supported": True,
    }
    for key, value in overrides.items():
        if value is None:
            md.pop(key, None)
        else:
            md[key] = value
    return md


def mount(
    router: respx.MockRouter,
    *,
    mcp_url: str = MCP,
    resource: str | None = MCP,
    issuers: tuple[str, ...] = (AS,),
    header: bool = True,
    header_url: str | None = PRM_PATH,
    prm_urls: tuple[str, ...] = (PRM_PATH,),
    prm_extra: dict[str, Any] | None = None,
    unauth_status: int = 401,
    metadata: dict[str, dict[str, Any]] | None = None,
    metadata_urls: dict[str, str] | None = None,
    token_error: tuple[int, str, str] = (400, "application/json", '{"error":"invalid_grant"}'),
    dcr: tuple[int, str, str] = (
        201,
        "application/json",
        '{"client_id":"abc","token_endpoint_auth_method":"none"}',
    ),
    mcp_handler=None,
) -> None:
    """Install the routes. `metadata` maps issuer to its metadata document (default: a
    correct one); `metadata_urls` maps issuer to the URL that serves it (default: the
    RFC 8414 root form)."""
    www = (
        f'Bearer resource_metadata="{header_url}", scope="mcp:read"'
        if header and header_url
        else None
    )

    def mcp(request: httpx.Request) -> httpx.Response:
        if mcp_handler is not None:
            return mcp_handler(request)
        headers = {"WWW-Authenticate": www} if www and unauth_status == 401 else {}
        if unauth_status == 200:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        return httpx.Response(unauth_status, headers=headers)

    router.post(mcp_url).mock(side_effect=mcp)

    prm: dict[str, Any] = {}
    if resource is not None:
        prm["resource"] = resource
    if issuers:
        prm["authorization_servers"] = list(issuers)
    prm.update(prm_extra or {})
    for url in prm_urls:
        router.get(url).mock(return_value=httpx.Response(200, json=prm))

    for issuer in issuers:
        md = (metadata or {}).get(issuer, as_metadata(issuer))
        url = (metadata_urls or {}).get(issuer, f"{issuer}/.well-known/oauth-authorization-server")
        router.get(url).mock(return_value=httpx.Response(200, json=md))
        status, ctype, body = token_error
        router.post(md.get("token_endpoint", f"{issuer}/token")).mock(
            return_value=httpx.Response(status, content=body, headers={"Content-Type": ctype})
        )
        if md.get("registration_endpoint"):
            status, ctype, body = dcr
            router.post(md["registration_endpoint"]).mock(
                return_value=httpx.Response(status, content=body, headers={"Content-Type": ctype})
            )

    router.route().mock(return_value=httpx.Response(404, content="not found"))


def form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def body_json(request: httpx.Request) -> Any:
    return json.loads(request.content.decode())


def by_id(report, check_id: str, issuer: str | None = None):
    for check in report.checks:
        if check.id == check_id and (issuer is None or check.evidence.get("issuer") == issuer):
            return check
    raise AssertionError(f"no check {check_id!r} in {[c.id for c in report.checks]}")
