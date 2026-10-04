import httpx

from mcp_auth_doctor.mcpclient import initialize_request, mcp_headers, parse_jsonrpc_response


def test_parse_json_body():
    response = httpx.Response(200, json={"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
    assert parse_jsonrpc_response(response, 2)["result"] == {"tools": []}


def test_parse_sse_body_picks_matching_id():
    text = (
        'event: message\ndata: {"jsonrpc":"2.0","id":9,"result":{}}\n\n'
        'event: message\ndata: {"jsonrpc":"2.0",\n'
        'data: "id":2,"result":{"tools":[{"name":"a"}]}}\n\n'
    )
    response = httpx.Response(200, content=text, headers={"Content-Type": "text/event-stream"})
    assert parse_jsonrpc_response(response, 2)["result"]["tools"][0]["name"] == "a"
    assert parse_jsonrpc_response(response, 3) is None


def test_parse_batch_and_garbage():
    batch = httpx.Response(200, json=[{"jsonrpc": "2.0", "id": 2, "result": {}}])
    assert parse_jsonrpc_response(batch, 2) == {"jsonrpc": "2.0", "id": 2, "result": {}}
    assert parse_jsonrpc_response(httpx.Response(200, content="nope"), 2) is None


def test_headers_and_initialize_body():
    headers = mcp_headers("2025-11-25", token="t", session="s")
    assert headers["Authorization"] == "Bearer t"
    assert headers["Mcp-Session-Id"] == "s"
    assert headers["MCP-Protocol-Version"] == "2025-11-25"
    body = initialize_request("2026-07-28")
    assert body["params"]["protocolVersion"] == "2026-07-28"
    assert body["params"]["clientInfo"]["name"] == "mcp-auth-doctor"
