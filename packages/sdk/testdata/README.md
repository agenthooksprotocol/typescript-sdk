# SDK authentication lifecycle vectors

The canonical source is `agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json`, proposed in [protocol PR #44](https://github.com/agenthooksprotocol/agent-hooks-protocol/pull/44). `sdk-auth-lifecycle.json` in this directory is an exact byte-for-byte copy.

SHA-256: `4b7f03758ebdba268d9ed218aa7c739c8a1207e9561c52e8f99b657a3eca2f97`.

Native tests consume the recovery, key and eight token-response vectors. The 16 lifecycle entries are a coverage manifest, not executable proof. `pnpm check` builds and executes the native HTTPS/store/transport regressions in `packages/sdk/test/oauth*.test.mjs`, along with the remaining SDK suites and packed-package verification.
