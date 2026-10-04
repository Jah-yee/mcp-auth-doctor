import pytest

from mcp_auth_doctor.discovery import (
    UrlError,
    as_metadata_urls,
    bearer_scope,
    canonical,
    compare_resource,
    is_json_content_type,
    issuer_matches,
    parse_www_authenticate,
    prm_well_known_urls,
    resource_metadata_url,
    validate_mcp_url,
)


def test_prm_urls_path_aware_then_root():
    assert prm_well_known_urls("https://example.com/public/mcp") == [
        "https://example.com/.well-known/oauth-protected-resource/public/mcp",
        "https://example.com/.well-known/oauth-protected-resource",
    ]


def test_prm_urls_root_only_without_path():
    assert prm_well_known_urls("https://example.com") == [
        "https://example.com/.well-known/oauth-protected-resource"
    ]
    assert prm_well_known_urls("https://example.com/") == [
        "https://example.com/.well-known/oauth-protected-resource"
    ]


def test_prm_urls_trailing_slash_path_tries_strict_then_stripped():
    assert prm_well_known_urls("https://example.com:8443/mcp/") == [
        "https://example.com:8443/.well-known/oauth-protected-resource/mcp/",
        "https://example.com:8443/.well-known/oauth-protected-resource/mcp",
        "https://example.com:8443/.well-known/oauth-protected-resource",
    ]


def test_as_urls_with_path_component_follow_mcp_priority():
    assert as_metadata_urls("https://auth.example.com/tenant1") == [
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
        "https://auth.example.com/.well-known/openid-configuration/tenant1",
        "https://auth.example.com/tenant1/.well-known/openid-configuration",
    ]


def test_as_urls_without_path_component():
    assert as_metadata_urls("https://auth.example.com/") == [
        "https://auth.example.com/.well-known/oauth-authorization-server",
        "https://auth.example.com/.well-known/openid-configuration",
    ]


def test_parse_www_authenticate_quoted_and_unquoted():
    header = (
        'Bearer realm="mcp", resource_metadata="https://x/.well-known/oauth-protected-resource", '
        "scope=files:read"
    )
    challenges = parse_www_authenticate(header)
    assert len(challenges) == 1
    assert challenges[0].scheme == "Bearer"
    assert (
        challenges[0].params["resource_metadata"]
        == "https://x/.well-known/oauth-protected-resource"
    )
    assert challenges[0].params["scope"] == "files:read"
    assert bearer_scope(header) == "files:read"


def test_parse_www_authenticate_multiple_challenges_and_case():
    header = 'Basic realm="r", bearer RESOURCE_METADATA="https://x/prm", error="invalid_token"'
    challenges = parse_www_authenticate(header)
    assert [c.scheme for c in challenges] == ["Basic", "bearer"]
    assert resource_metadata_url(header) == "https://x/prm"


def test_parse_www_authenticate_escaped_quote_and_garbage():
    assert parse_www_authenticate('Bearer realm="a\\"b"')[0].params["realm"] == 'a"b'
    assert parse_www_authenticate("") == []
    assert resource_metadata_url("Bearer") is None
    assert resource_metadata_url('Digest resource_metadata="https://x"') is None


def test_compare_resource_exact_and_normalised():
    assert compare_resource("https://a.example/mcp", "https://a.example/mcp").ok
    assert compare_resource("HTTPS://A.example:443/mcp", "https://a.example/mcp").ok
    assert canonical("https://a.example:8443/mcp") == "https://a.example:8443/mcp"


def test_compare_resource_trailing_slash_is_flagged():
    match = compare_resource("https://a.example/mcp", "https://a.example/mcp/")
    assert not match.ok
    assert match.trailing_slash_only
    assert "trailing slash" in match.reason
    assert "resource has the slash" in match.reason
    other = compare_resource("https://a.example/mcp/", "https://a.example/mcp")
    assert other.trailing_slash_only and "MCP URL has the slash" in other.reason


def test_compare_resource_other_mismatch():
    match = compare_resource("https://a.example/mcp", "https://a.example/other")
    assert not match.ok and not match.trailing_slash_only


def test_validate_mcp_url_rules():
    assert validate_mcp_url("https://a.example/mcp") == "https://a.example/mcp"
    assert validate_mcp_url("http://localhost:3000/mcp")
    assert validate_mcp_url("http://127.0.0.1:3000/mcp")
    with pytest.raises(UrlError):
        validate_mcp_url("http://a.example/mcp")
    with pytest.raises(UrlError):
        validate_mcp_url("ftp://a.example/mcp")
    with pytest.raises(UrlError):
        validate_mcp_url("https://a.example/mcp#frag")
    with pytest.raises(UrlError):
        validate_mcp_url("https:///mcp")


def test_issuer_matches_and_content_type():
    assert issuer_matches("https://as.example", "https://as.example/")
    assert not issuer_matches("https://as.example", "https://other.example")
    assert not issuer_matches("https://as.example", None)
    assert is_json_content_type("application/json; charset=utf-8")
    assert is_json_content_type("application/problem+json")
    assert not is_json_content_type("application/x-www-form-urlencoded")
    assert not is_json_content_type(None)
