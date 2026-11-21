# SDK authentication lifecycle vectors

The canonical source is `agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json` at the protocol ref pinned in `.github/workflows/ci.yml` and `src/draft/ahp-codegen.lock.json`. `sdk-auth-lifecycle.json` in this directory is an exact byte-for-byte copy; `test/auth-lifecycle-contract.test.mjs` checks this against the pinned ref.

SHA-256: `c30b0aec201acfeb31fb5b0c2a6d19cc64f91fbfb76814b8a8a4f475d8e8e4e8`.

Native tests consume the recovery, key, token-response, scope-decision, completion, token-error, registration-key, client-selection and registration-response vectors; `test/auth-vectors.test.mjs` runs every scope-decision, completion and token-error vector, asserting every field each defines. A vector's `requires` is matched against the SDK features declared in `test/fixtures/sdk-features.mjs`: TypeScript has `legacy_prepare_time_host_required` but neither `token_validation_callback` nor `complete_handle`, so vectors requiring those two are skipped, and a vector naming an unknown feature fails the suite. Each lifecycle id is the leading `[id]` tag of a native test at real store, network and transport boundaries; the contract test fails when an id has no test.

`tls/` holds a static, insecure, test-only localhost certificate and key for the HTTPS tests. This directory is not part of the published package.
