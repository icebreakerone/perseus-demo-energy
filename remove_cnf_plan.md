# Remove certificate thumbprint binding (`cnf.x5t#S256`), align with Perseus spec

## Context

The [Perseus spec](https://specification.trust.ib1.org/oauth-with-member-identity-certificates/1.0/) states:

> "Tokens are bound to the Directory URL from the certificate (rather than to the specific certificate instance) by requiring that the `client_id` matches the certificate."

The current code does **both**:
1. Binds via `client_id` (Directory URL from certificate) — **correct per spec**
2. Binds via `cnf.x5t#S256` (SHA256 certificate thumbprint) — **leftover from FAPI 2.0 / RFC 8705**

The thumbprint binding ties a token to a specific certificate instance. The Perseus spec explicitly wants binding to the Directory URL instead, so tokens remain valid if a certificate is rotated/reissued (as long as the same application identity is present). The `client_id` check already achieves this.

The `tls_client_certificate_bound_access_tokens: true` metadata stays — the spec requires it. Tokens are still mTLS-bound, just via `client_id` matching rather than thumbprint.

## Changes

### 1. Authentication API — token creation (`authentication/api/auth.py`)
- **Remove** `get_thumbprint()` function (lines 63-71)
- **Remove** `claims["cnf"] = {"x5t#S256": get_thumbprint(client_certificate)}` from `create_enhanced_access_token()` (line 99)
- Update comment on line 227 of `authentication/api/main.py` ("Add in our required client certificate thumbprint" → something about client_id binding)
- **Remove** unused imports: `base64`, `hashes` from `auth.py`

### 2. Authentication API — model (`authentication/api/models.py`)
- **Remove** the `Cnf` class (lines 79-80) — unused elsewhere

### 3. Authentication API — tests (`authentication/tests/test_auth.py`)
- Remove `get_thumbprint` from imports (line 19)
- Update `test_create_enhanced_access_token`: replace `cnf`/`x5t#S256` assertions (lines 136-138) with assertions that `client_id` is set correctly

### 4. Resource API — token validation (`resource/api/auth.py`)
- **Remove** `check_certificate()` function entirely (lines 27-73)
- **Remove** the call `check_certificate(cert, decoded)` in `check_token()` (line 132)
- **Remove** unused imports: `base64`, `hashes`, `AccessTokenCertificateError`

### 5. Resource API — exceptions (`resource/api/exceptions.py`)
- **Remove** `AccessTokenCertificateError` class (lines 55-56) — no longer raised anywhere

### 6. Resource API — tests (`resource/tests/test_auth.py`)
- Remove `@patch("api.auth.check_certificate")` and `mock_check_certificate` from `test_check_token_valid` (lines 87, 91, 106-108)

### 7. Resource API — test fixture (`resource/tests/fixtures/jwt.json`)
- **Remove** the `cnf` block (lines 27-29)

### 8. Authentication CLAUDE.md (`authentication/CLAUDE.md`)
- Update `api/auth.py` description: "certificate thumbprint extraction" → "client_id extraction from certificates"

## Verification

```bash
cd authentication && pipenv run pytest -s tests/
cd resource && pipenv run pytest -s tests/
```
