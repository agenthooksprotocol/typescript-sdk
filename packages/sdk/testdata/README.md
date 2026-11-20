# SDK authentication lifecycle vectors

The canonical source is `agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json` at the protocol ref pinned in `.github/workflows/ci.yml` and `src/draft/ahp-codegen.lock.json`. `sdk-auth-lifecycle.json` in this directory is an exact byte-for-byte copy; `test/auth-lifecycle-contract.test.mjs` checks this against the pinned ref.

SHA-256: `4854c9d04394d45deae1225e55b868f9c93c2c52c6166e3354a521d04fe15c84`.

Native tests consume the recovery, key, token-response, scope-decision, completion, registration-key, client-selection and registration-response vectors; `test/auth-vectors.test.mjs` runs every scope-decision and completion vector. A vector's `requires` is matched against the SDK features declared in `test/fixtures/sdk-features.mjs`: TypeScript has neither `token_validation_callback` nor `complete_handle`, so vectors requiring them are skipped, and a vector naming an unknown feature fails the suite. Each lifecycle id is the leading `[id]` tag of a native test at real store, network and transport boundaries; the contract test fails when an id has no test.

`tls/` holds a static, insecure, test-only localhost certificate and key for the HTTPS tests. This directory is not part of the published package.
