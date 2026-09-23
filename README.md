# OVSE Integration Test Portal - API-backed prototype

This version is intentionally not hardcoded.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000

## Real API calls

- `POST /api/validate-jwt` validates the submitted JWT with the supplied RSA public key.
- `POST /api/test-callback` makes a real HTTPS POST to the supplied callback URL.
- SQLite stores used `jti` values for replay detection.

## Important production controls

Before exposing this externally, add portal authentication/authorization, approved endpoint allowlisting, SSRF protections, rate limiting, audit logging, secret/key management, environment separation and network egress controls.
