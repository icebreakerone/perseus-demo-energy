# Remove `x-fapi-interaction-id` and the provenance `transaction` field, align with IB1 specs

## Context

Two coupled divergences, both leftovers from FAPI 2.0 (directly analogous to the
`cnf` thumbprint binding targeted by [`remove_cnf_plan.md`](remove_cnf_plan.md)):

1. **`x-fapi-interaction-id` header.** The
   [OAuth profile](https://specification.trust.ib1.org/oauth-with-member-identity-certificates/1.0/)
   lists `x-fapi-*` headers under **Unused options**:

   > "The additional `x-fapi-*` headers defined in the FAPI 2 implementation advice … are [not used], as better functionality is provided by other Trust Framework specifications."

   The resource server nonetheless accepts an inbound `x-fapi-interaction-id`,
   generates one if absent, and returns it on every protected response.

2. **Provenance `transaction` field.** The resource server threads that
   interaction id into the provenance **transfer** step as `"transaction": fapi_id`.
   But the [Provenance Records spec](https://specification.trust.ib1.org/provenance-records/1.0/)
   defines the transfer step as exactly
   `id, type, timestamp, of, to, scheme, standard, license, service, path, parameters, permissions` —
   **the word `transaction` never appears in the spec.** It is also not a valid
   scheme-namespaced extension (the spec requires custom properties to be prefixed
   `<scheme>:property`, as the code already does for `perseus:scheme` /
   `perseus:assurance`). The `ib1-provenance` library passes the key through
   verbatim into the signed record, so this repo owns the divergence.

The interaction id's *only* internal consumer is that `transaction` field. Once it
is removed, the header is pure dead weight, so both are removed together.

The HTTP `Date` response header (a standard header, not an `x-fapi-*` header) is
**kept**.

## Changes

### 1. Resource API — token validation (`resource/api/auth.py`)
- **Remove** the `x_fapi_interaction_id: Optional[str] = None` parameter from
  `check_token()` (line 103).
- **Remove** the interaction-id block (lines 137–143): the `if x_fapi_interaction_id
  is None` generation and `headers["x-fapi-interaction-id"] = …`.
- **Keep** `headers["Date"] = email.utils.formatdate()` (line 135).
- Update the `check_token()` docstring (lines 112–113) — drop the
  "including Date and x-fapi-interaction-id" wording, leave "Date".
- **Remove** now-unused imports: `import uuid` (line 1) and `Optional` from
  `from typing import Optional, Tuple` → `from typing import Tuple` (`Tuple` is
  still used in the return annotation).

### 2. Resource API — request handling (`resource/api/main.py`)
- **Remove** the `x_fapi_interaction_id: Annotated[str | None, Header()] = None`
  parameter from `require_mtls_and_token()` (line 35) and the argument passed to
  `check_token(...)` (line 83).
- **Remove** the `fapi_id=headers["x-fapi-interaction-id"]` argument from the
  `create_provenance_records(...)` call in `consumption()` (line 154).

### 3. Resource API — provenance (`resource/api/provenance.py`)
- **Remove** the `fapi_id: str` parameter from `create_provenance_records()`
  (line 28).
- **Remove** `"transaction": fapi_id,` from the transfer step (line 109).

### 4. Resource API — tests
- `tests/test_auth.py`: remove `assert "x-fapi-interaction-id" in headers`
  (line 104); keep `assert "Date" in headers`.
- `tests/test_provenance.py`: remove `fapi_id = "fapi123"` (line 62) and the
  `fapi_id,` positional argument in the `create_provenance_records(...)` call
  (line 73).
- `tests/test_api.py`: in `test_datasources` and `test_consumption`, change the
  mocked `check_token` return headers from `{"x-fapi-interaction-id": "123"}` to
  `{"Date": "..."}` (or `{}`) (lines 69, 113); remove `fapi_id="123"` from the
  `mock_create_provenance_records.assert_called_once_with(...)` (line 143).

### 5. Resource API — OpenAPI docs (`resource/api/openapi.py`)
- Drop the `x-fapi-interaction-id` mention from `API_DESCRIPTION` (line 33).
  *(Overlaps with the in-progress OpenAPI documentation task — coordinate so the
  two passes don't conflict.)*

## Decision point

**Should the `x-fapi-interaction-id` response header be removed entirely, or kept
for client compatibility?** Full spec alignment = remove it (this plan's default).
Removing it is a client-visible behaviour change: any FAPI 2 client that expects
the server to echo its interaction id will no longer receive it. For a demo this is
acceptable; confirm before applying if any known consumer depends on it.

## Out of scope / flagged for separate verification

- **`licence` vs `license` spelling.** The code uses British spelling
  (`provenance.py:62,63,75,100`: `licences`, `originLicence`, `licence`) while the
  spec's rendered examples show American `license`. **Unverified** — the spec was
  read via an automated fetch that may have normalised the spelling, and IB1 is a
  UK organisation, so the spec may well use `licence`. Do not change until checked
  against the raw spec source.

## Verification

```bash
cd resource && pipenv run pytest -s tests/
cd resource && pipenv run ruff check .
```
