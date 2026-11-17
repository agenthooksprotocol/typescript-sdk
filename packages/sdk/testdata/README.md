# SDK authentication lifecycle vectors

The canonical source is `agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json` at the protocol ref pinned in `.github/workflows/ci.yml` and `src/draft/ahp-codegen.lock.json`. `sdk-auth-lifecycle.json` in this directory is an exact byte-for-byte copy; `test/auth-lifecycle-contract.test.mjs` checks this against the pinned ref.

SHA-256: `b7a38f59a1c29a5e757ab8dfa057ab9a079a161092a9325067813077aefc9868`.

Native tests consume the recovery, key and token-response vectors. Each lifecycle id is the leading `[id]` tag of a native test at real store, network and transport boundaries; the contract test fails when an id has no test.

`tls/` holds a static, insecure, test-only localhost certificate and key for the HTTPS tests. This directory is not part of the published package.
