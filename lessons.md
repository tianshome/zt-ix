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

- Symptom: Host-side authenticated probes to ZeroTier local controller API (`/status`, `/controller`) returned `401`, while in-container probes returned `200`.
- Root cause: ZeroTier management API allowlist defaults did not include host-originated requests from Docker bridge/NAT path; container-local loopback requests still passed.
- Rule to prevent recurrence: In compose-based controller runtime, mount a managed `local.conf` with `settings.allowManagementFrom` set appropriately (current repo baseline: `["0.0.0.0/0"]`) and keep API port binding restricted to `127.0.0.1` on host.
- Example (good vs bad):
  - Good: `docker/zerotier/local.conf` mounted to `/var/lib/zerotier-one/local.conf` with `allowManagementFrom` configured, then host probe `curl -H "X-ZT1-Auth: ${ZT_CONTROLLER_AUTH_TOKEN}" http://127.0.0.1:9993/status` returns `200`.
  - Bad: No explicit `allowManagementFrom` config -> host probe returns `401` while `docker compose exec ... curl http://127.0.0.1:9993/status` still returns `200`.
