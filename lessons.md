# lessons.md

- Symptom: Valid PeeringDB OAuth login returned `/error?code=invalid_nonce` during real browser integration.
- Root cause: PeeringDB OAuth application registration used the wrong token-signing algorithm; callback flow only succeeded after setting algorithm to `RSA with SHA-2 256` (RS256).
- Rule to prevent recurrence: During OAuth app registration or credential rotation, verify `PEERINGDB_SCOPES` includes `openid` and the PeeringDB app algorithm is explicitly set to `RSA with SHA-2 256` before running integration tests.
- Example (good vs bad):
  - Good: PeeringDB app configured with RS256 + app scopes include `openid profile email networks` -> callback reaches `/onboarding`.
  - Bad: Missing RS256 setting or missing `openid` scope -> callback may fail with nonce/id_token validation errors.

- Symptom: Generated BIRD route-server snippet failed parse with `unexpected IMPORT` and `Filter name required`.
- Root cause: BIRD 3 requires per-family channel blocks (`ipv4 { ... };` / `ipv6 { ... };`) and `filter` definitions (not `function`) when referenced by `import filter`.
- Rule to prevent recurrence: Validate generated snippets with `bird -p -c ...` and keep BGP policy syntax in BIRD 3 channel format before merging route-server config changes.
- Example (good vs bad):
  - Good: `filter ztix_roa_guard_v4 { ... }` plus `ipv4 { import filter ztix_roa_guard_v4; ... };`.
  - Bad: `function ztix_roa_guard_v4() { ... }` with top-level `import filter ...` directly under protocol.
