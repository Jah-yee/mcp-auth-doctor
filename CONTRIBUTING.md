# Contributing

Thanks for considering a contribution. The project is small on purpose: one HTTP conversation, a list of checks, two renderers. The most useful contributions are new checks backed by a spec citation and a real-world report, and fixtures reproducing failures people hit with actual servers.

## Set up

Requires Python 3.11 or newer and [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/basitalisandhu/mcp-auth-doctor
cd mcp-auth-doctor
uv venv && uv pip install -e ".[dev]"
uv run pytest -q
```

Without uv:

```bash
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install -e ".[dev]"
python3 -m pytest -q
```

## Before you open a pull request

```bash
make check          # ruff check, ruff format --check, pytest
```

CI runs the same on Python 3.11 and 3.12, builds the wheel and runs it against `scripts/demo_server.py` in both its correct and `--broken` modes.

## Adding a check

1. Implement it in `src/mcp_auth_doctor/checks.py` as a call to `self.add(<id>, <status>, <reason>, **evidence)`. Ids are lower-case words joined by hyphens and prefixed by the stage they belong to (`prm-`, `as-`, `login-`). Statuses are `pass`, `fail`, `warn` or `skip`; `fail` makes the exit code 1, so reserve it for things that stop a conforming MCP client from connecting.
2. The reason is one line, says what was observed and what the server should do instead, and cites the rule (RFC section or MCP spec page) when there is one.
3. Add the id and the fix advice to the check table in `README.md`, and to the docstring at the top of `checks.py`, in execution order.
4. Add a test in `tests/test_checks.py` using the `mount()` fixture from `tests/conftest.py`; one positive and one negative case. If the check needs a new fixture knob, add a keyword to `mount()` with a correct default so existing tests are unaffected.
5. If the check depends on the spec version, branch on `self.options.spec` and test both values.

## Style

- `ruff` formats and lints; line length 100.
- Plain language in reasons: say what the server returned and what a client does with it.
- Deterministic output: no timestamps, no random ids in reports (random values are fine inside requests, such as PKCE verifiers).
- No model names or vendor identifiers in the repository.
- The tool reads by default. Anything that creates server-side state (registration, tokens) must stay behind an explicit flag and be described in `SECURITY.md`.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
