# Dependency audit

Last reviewed 2026-11-18 with `pip-audit` and `npm audit`. Re-run the commands at the end before relying on these numbers.

## Summary

| Dependency set | Used for | Known advisories | What can be done |
|---|---|---|---|
| `requirements.txt` | The application server | 0 | Nothing needed |
| `requirements-dev.txt` | Tests | 0 | Nothing needed |
| `package.json` | Building the UI | 1 (picomatch, via Vite) | No patched release exists |
| `requirements-cai.lock` | The optional CAI SDK interpreter | 50 across 8 packages | Blocked by upstream pins; see below |

## UI build: picomatch

`npm audit` reports a regular-expression denial of service in picomatch (GHSA-fc5q-39xc-vjpf), reached through Vite, fdir and tinyglobby. Every released picomatch is affected, including the latest (4.0.7), so there is no version to move to. npm's suggested "fix" is to downgrade Vite to 6.2.7, which would give up later Vite fixes.

picomatch matches file globs while the UI is built. It is not part of the served application, and the build's glob patterns come from this repository. Re-check when a patched picomatch is published.

## Optional CAI SDK environment

The CAI SDK runs in its own interpreter (`.venv-cai`), installed only when you choose to use CAI. Its lockfile carries the SDK's whole dependency closure.

### Why it cannot be upgraded

`cai-framework` 0.5.10 is the newest release. It requires `litellm[proxy]>=1.63.7`, `openai==1.75.0` and `rich>=13.9.4`. Together those make LiteLLM 1.68.0 the newest release that resolves (older ones back to 1.63.7 also do, and fix nothing):

- LiteLLM 1.68.1 to 1.75.3 still accept that OpenAI client, but their proxy extra pins `rich==13.7.1`, which CAI's own `rich>=13.9.4` rules out.
- LiteLLM 1.75.4 and later require `openai>=1.99.5`, which CAI's `openai==1.75.0` rules out.

LiteLLM 1.68.0's proxy extra then pins the rest:

| Package | Locked | Advisories | Held by |
|---|---|---|---|
| litellm | 1.68.0 | 23 | CAI's `openai==1.75.0` and `rich>=13.9.4`, as above |
| starlette | 0.46.2 | 7 | fastapi `<0.116` (LiteLLM) → starlette `<0.47` |
| cryptography | 43.0.3 | 6 | LiteLLM `<44` |
| python-multipart | 0.0.18 | 6 | LiteLLM `<0.0.19` |
| mcp | 1.5.0 | 5 | LiteLLM `==1.5.0` |
| fastapi-sso | 0.16.0 | 1 | LiteLLM `<0.17` |
| pypdf2 | 3.0.1 | 1 | Final PyPDF2 release; the fix is in the renamed `pypdf` |
| cai-framework | 0.5.10 | 1 | No fixed release |

The lock was refreshed on this date. Of its 148 pins, 27 changed, which cleared the only two advisories a re-resolve could reach (dnspython and oauthlib). The 18 CAI SDK tests pass on the refreshed lock.

### What is and is not exposed

- **LiteLLM (23), Starlette (7), python-multipart (6), fastapi-sso (1), MCP (5).** These are in server code: the LiteLLM proxy's endpoints, authentication and UI, and the MCP server transports. AI-tricky never starts the LiteLLM proxy or an MCP server. The worker talks to the model endpoint directly with its own client, and nothing in that interpreter listens for connections. Importing the SDK does load the `litellm.proxy` package and Starlette, but not the proxy server module.
- **cai-framework (CVE-2026-25130).** Argument injection in the SDK's built-in function tools. AI-tricky does not register those tools; the agent gets only AI-tricky's own scoped fetch and probe tools, or none in evidence-only mode.
- **PyPDF2.** A crafted PDF can hang the parser. AI-tricky does not parse PDFs.
- **cryptography (6).** Certificate-validation and bundled-OpenSSL issues. These were not traced call by call. TLS to the model endpoint is handled by Python's `ssl` module through httpx, not by this package, but treat this row as unverified.

Not exposed is not the same as fixed. Do not run `litellm --proxy`, an MCP server, or the CAI command-line agent from `.venv-cai` on a machine you care about, and do not install this lockfile into the main application environment.

The advisories clear only when CAI publishes a release that accepts a newer OpenAI client (LiteLLM releases compatible with CAI's `rich` requirement need OpenAI client 2.8.0 or later). Moving to a different CAI version is a compatibility change, not a lockfile refresh: the adapter and the SDK tests are written against 0.5.10.

## Re-running the audit

```
python -m pip install pip-audit
python -m pip_audit -r requirements.txt
python -m pip_audit -r requirements-dev.txt
python -m pip_audit -r requirements-cai.lock --no-deps --disable-pip
npm audit
```

To refresh the CAI lock, use the Python version CI uses for that job (3.12). `--clear` empties the environment first, so a second run cannot keep stale pins:

```
python3.12 -m venv --clear /tmp/cai-lock
/tmp/cai-lock/bin/python -m pip install -r requirements-cai.txt pytest==9.2.0
/tmp/cai-lock/bin/python -m pip freeze --exclude pip --exclude setuptools --exclude wheel > requirements-cai.lock
CAI_TEST_PYTHON=/tmp/cai-lock/bin/python /tmp/cai-lock/bin/python -m pytest \
  backend/tests/test_cai_sdk.py backend/tests/test_cai_usage_sdk.py backend/tests/test_team_routing_sdk.py -q
```
