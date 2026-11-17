# SDK authentication lifecycle vectors

The canonical source is `agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json` at the protocol ref pinned in `.github/workflows/ci.yml` and `src/draft/ahp-codegen.lock.json`. `sdk-auth-lifecycle.json` in this directory is an exact byte-for-byte copy; `test/auth-lifecycle-contract.test.mjs` checks this against the pinned ref.

SHA-256: `0be8aff81a93142dcc0094a8cc953d140ab5db9714422ede9ce040f34604a731`.

Native tests consume the recovery, key and token-response vectors. Each lifecycle id is the leading `[id]` tag of a native test at real store, network and transport boundaries; the contract test fails when an id has no test.

`tls/` holds a static, insecure, test-only localhost certificate and key for the HTTPS tests. This directory is not part of the published package.
