# Divergences from IB1 Trust Framework specifications

Tracking list of points where the implementation (or its docs) diverges from the
IB1 Trust Framework specifications. This is the working todo list for removing or
correcting each divergence.

Reference specifications:

- **Certificates** — [Member Identity Digital Certificates 1.0](https://specification.trust.ib1.org/member-identity-digital-certificates/1.0/)
- **OAuth** — [OAuth with Member Identity Certificates 1.0](https://specification.trust.ib1.org/oauth-with-member-identity-certificates/1.0/#oauth-profile)
- **Provenance** — [Provenance Records 1.0](https://specification.trust.ib1.org/provenance-records/1.0/)

Status legend: ✅ resolved · 📝 plan ready · 🔧 open (needs work) · ❓ unverified

---

## 1. `cnf.x5t#S256` certificate-thumbprint token binding 📝

**Spec (OAuth):** "Tokens are bound to the Directory URL from the certificate
(rather than to the specific certificate instance) by requiring that the
`client_id` matches the certificate." The profile does **not** use `cnf`,
`x5t#S256`, thumbprints, or RFC 8705.

**Current behaviour:** the token is bound **both** ways — by `client_id`
(spec-correct) **and** by a `cnf.x5t#S256` SHA-256 thumbprint (FAPI 2.0 / RFC 8705
leftover):
- `authentication/api/auth.py` — `create_enhanced_access_token()` adds the `cnf`
  claim; `get_thumbprint()` computes it.
- `resource/api/auth.py` — `check_certificate()` (lines 27–73) enforces the
  thumbprint; called from `check_token()` (line 132).

**Action:** remove the thumbprint binding, keep `client_id` matching.
**Plan:** [`remove_cnf_plan.md`](remove_cnf_plan.md)

- [ ] Execute `remove_cnf_plan.md`

---

## 2. `x-fapi-interaction-id` header 📝

**Spec (OAuth, "Unused options"):** "The additional `x-fapi-*` headers defined in
the FAPI 2 implementation advice … are [not used], as better functionality is
provided by other Trust Framework specifications."

**Current behaviour:** the resource server accepts an inbound
`x-fapi-interaction-id`, generates one if absent, and returns it on every
protected response:
- `resource/api/auth.py` — `check_token()` param + generation block (lines 137–143).
- `resource/api/main.py` — `require_mtls_and_token()` header param + call site.

The request param is currently hidden from the OpenAPI docs via
`Header(include_in_schema=False)`, but the runtime behaviour remains.

**Action:** remove the header handling.
**Plan:** [`remove_fapi_interaction_id_plan.md`](remove_fapi_interaction_id_plan.md)

- [ ] Execute `remove_fapi_interaction_id_plan.md` (covers items 2 and 3)

---

## 3. Provenance `transaction` field 📝

**Spec (Provenance):** the `transfer` step is defined as exactly
`id, type, timestamp, of, to, scheme, standard, license, service, path,
parameters, permissions`. The word `transaction` **never appears** in the spec,
and it is not a valid scheme-namespaced extension (custom properties must be
prefixed `<scheme>:property`).

**Current behaviour:** `resource/api/provenance.py:109` adds
`"transaction": fapi_id` (the `x-fapi-interaction-id`) to the transfer step, which
the `ib1-provenance` library writes verbatim into the signed record.

**Action:** remove the `transaction` field (coupled with item 2 — it is the only
consumer of the interaction id).
**Plan:** [`remove_fapi_interaction_id_plan.md`](remove_fapi_interaction_id_plan.md)

- [ ] Covered by the plan in item 2

---

## 4. License text for informed consent — handled client-side (CAP app) ✅

**Spec (OAuth):** "The Registry License URL is used as the `scope`, and provides
the text which must be displayed to the end-user to give informed consent."

**Current behaviour:**
- The `scope` (license URL) **is** threaded through: accepted at
  `/api/v1/par` (`authentication/api/main.py:71,98`), forwarded to Ory Hydra
  (`main.py:148`), and stored as the permission `license`
  (`permissions.py:154`, from `scp[0]`).
- But **nothing dereferences the Registry License URL** to obtain its consent
  text. The login/consent screen is delegated to an external Ory Hydra instance
  (`conf.py:31`), there is no consent template in this repo (only `base`, `error`,
  `evidence`), and the license is only ever rendered as a raw URL string
  (`templates/evidence.html:19`). `compose.yml` wires up no consent UI service.

So the "display the license text for informed consent" requirement is **not
implemented in this repository's authentication flow**.

**Resolution (confirmed):** this is **not a divergence**. The license consent text
is displayed **client-side, in the CAP (Consumer Access Provider) application**,
not in this authentication server's flow. The requirement is satisfied; no change
needed here.

- [x] Confirmed: consent text is shown by the CAP app, outside this repo.

---

## 5. `licence` vs `license` field/path spelling ✅

**Verified against the machine-readable registry**
(`https://registry.core.sandbox.trust.ib1.org/registry.ttl`): the spelling is
American **`license`** throughout (16×, zero `licence`). The earlier "unverified"
caveat is resolved — IB1 uses `license` despite being a UK org.

**Resolution:** `resource/api/provenance.py` was corrected to American spelling in
both URL paths and provenance JSON field names (`licences`→`licenses`,
`licence`→`license`, `originLicence`→`originLicense`). British `licence` now only
remains in **external** source URL *values* (e.g. `smartenergycodecompany.co.uk`),
which we don't control. Done as part of the registry-config + scope normalization.

- [x] Verified spelling in the machine-readable registry (`license`).
- [x] Corrected provenance step field names and our own URL paths.

---

## 6. Scope value not validated as a Registry License URL ❓ (minor / robustness)

**Spec (OAuth):** the `scope` is a Registry License URL.

**Current behaviour:** `/api/v1/par` (`authentication/api/main.py:71`) accepts the
`scope` form field and passes it through without validating that it is a
well-formed Registry License URL. This is a demo trusting client input rather than
a behavioural contradiction of the spec.

- [ ] Decide whether to validate the `scope` is a Registry License URL at the PAR
      endpoint.

---

## Notes

- Items 1–3 already have detailed implementation plans and are ready to execute.
- Item 4 is resolved — satisfied client-side in the CAP app, no change needed here.
- Item 5 is resolved — spelling corrected to `license` per the machine-readable registry.
- Item 6 still needs a decision (scope-value validation).
- The OpenAPI documentation has already been updated to describe the
  **spec-aligned** end state (client_id binding, no `cnf`, no `x-fapi-*`); once
  items 1–3 land, code and docs will match. Until then, the docs are slightly
  ahead of the code on those points.
