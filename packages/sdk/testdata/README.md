# SDK authentication lifecycle vectors

The canonical source is `agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json` at the protocol ref pinned in `.github/workflows/ci.yml` and `src/draft/ahp-codegen.lock.json`. `sdk-auth-lifecycle.json` in this directory is an exact byte-for-byte copy; `test/auth-lifecycle-contract.test.mjs` checks this against the pinned ref.

SHA-256: `7ec04cc8fd7d53b6555e30d0999e144a34d615b58b45648d9e0b98d6dc7cd308`.

Native tests consume the recovery, key, token-response, scope-decision, completion, registration-key, client-selection and registration-response vectors; `test/auth-vectors.test.mjs` runs every scope-decision and completion vector, skipping only `host-policy-access-denied-scopes-stripped` (managedOAuth has no token-validation callback) and `complete-invalid-callback-state-mismatch` (`complete()` takes no pending-login handle). Each lifecycle id is the leading `[id]` tag of a native test at real store, network and transport boundaries; the contract test fails when an id has no test.

`tls/` holds a static, insecure, test-only localhost certificate and key for the HTTPS tests. This directory is not part of the published package.
