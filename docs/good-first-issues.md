# Good first issues

Issues the maintainer intends to open under the `good first issue` label, written out so
they can be filed in one sitting. Each is self-contained and has acceptance criteria that
`make check` can verify. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: `ruff` must pass,
every check needs a positive and a negative test against the `mount()` fixture, and
anything that writes to a server must stay behind an explicit flag.

## 1. Add a `prm-bearer-methods` check

**Context.** RFC 9728 lets protected resource metadata list `bearer_methods_supported`
(`header`, `body`, `query`). MCP clients only ever send the token in the `Authorization`
header, so a server that advertises `["query"]` or `["body"]` alone will reject every MCP
client.

**Acceptance criteria.**

- A new check `prm-bearer-methods` after `prm-authorization-servers`: `pass` when the
  member is absent or contains `header`; `fail` when it is present and does not contain
  `header`, with a reason naming the methods found.
- Tests in `tests/test_checks.py` for absent, `["header","body"]` and `["query"]`.
- Row added to the check table in `README.md` and to the docstring in `checks.py`.

## 2. Add an `as-https` check for endpoint URLs

**Context.** The MCP security considerations say every authorization server endpoint
MUST be served over HTTPS. The tool currently only verifies that the endpoints are
absolute URLs.

**Acceptance criteria.**

- A new check `as-https` after `as-endpoints`: `fail` when `authorization_endpoint`,
  `token_endpoint`, `registration_endpoint` or `jwks_uri` is present and does not start
  with `https://`, except for `localhost`, `127.0.0.1` and `::1` hosts, which `warn`
  instead so local development still works.
- Evidence lists each offending member and value.
- Tests cover an `http://` token endpoint on a public host, an `http://127.0.0.1` one,
  and the all-https default.

## 3. Add `--format markdown` for pasting the report into an issue

**Context.** People use the tool to report a problem to a server's maintainers. A
Markdown table of the checks (id, status, reason) pastes straight into a GitHub issue;
the text table does not render well there.

**Acceptance criteria.**

- `--format text|json|markdown`, with `--json` kept as an alias for `--format json`.
- `render_markdown()` in `src/mcp_auth_doctor/report.py`: a heading with the tool version,
  spec and URL, a three-column table, then a summary line identical to the text renderer.
- A test asserts the row count equals the number of checks and that a `fail` row keeps
  its reason verbatim.

## 4. Add a `-H/--header` option for extra request headers

**Context.** Some MCP servers sit behind an access proxy that wants an extra header (for
example a service-token header) before the real 401 is reachable. Without it the tool
reports the proxy's response instead of the server's.

**Acceptance criteria.**

- `-H "Name: value"`, repeatable, added to every request the tool sends to the MCP URL
  only (never to the authorization server or the token endpoint).
- `Authorization` is rejected with a usage error (exit 3), since the point of the first
  request is to be unauthenticated.
- Tests: a header is forwarded on the `initialize` POST and absent on the token POST;
  `-H "Authorization: x"` exits 3.

## 5. Warn when the challenge scope and `scopes_supported` disagree in kind

**Context.** The MCP spec says the `scope` in the `WWW-Authenticate` challenge is
authoritative and may differ from `scopes_supported`, but a challenge that asks for
scopes the protected resource metadata does not list at all is a frequent sign of a
misconfigured server (two components edited separately).

**Acceptance criteria.**

- A new check `prm-scopes` after `prm-authorization-servers`: `skip` when either value is
  absent; `pass` when every challenge scope is in `scopes_supported`; `warn` otherwise,
  listing the scopes that are missing. Never `fail`, because the spec permits it.
- Evidence carries both lists.
- Tests for the skip, pass and warn cases.
