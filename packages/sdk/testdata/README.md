# SDK authentication lifecycle vectors

The canonical source is `agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json`, proposed in [protocol PR #44](https://github.com/agenthooksprotocol/agent-hooks-protocol/pull/44). `sdk-auth-lifecycle.json` in this directory is an exact byte-for-byte copy.

SHA-256: `ef3d8f5ea5ef9c0036dfd23fcd65131f9c9a0a7e465c931d0265fc03f4938e2f`.

Native tests consume the recovery, key and nine token-response vectors. The 17 lifecycle entries are a coverage manifest, not executable proof. `pnpm check` builds and executes the native HTTPS/store/transport regressions in `packages/sdk/test/oauth*.test.mjs`, along with the remaining SDK suites and packed-package verification.
