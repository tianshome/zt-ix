# lessons.md

- Symptom: Valid PeeringDB OAuth login returned `/error?code=invalid_nonce` during real browser integration.
- Root cause: PeeringDB OAuth application registration used the wrong token-signing algorithm; callback flow only succeeded after setting algorithm to `RSA with SHA-2 256` (RS256).
- Rule to prevent recurrence: During OAuth app registration or credential rotation, verify `PEERINGDB_SCOPES` includes `openid` and the PeeringDB app algorithm is explicitly set to `RSA with SHA-2 256` before running integration tests.
- Example (good vs bad):
  - Good: PeeringDB app configured with RS256 + app scopes include `openid profile email networks` -> callback reaches `/onboarding`.
  - Bad: Missing RS256 setting or missing `openid` scope -> callback may fail with nonce/id_token validation errors.
