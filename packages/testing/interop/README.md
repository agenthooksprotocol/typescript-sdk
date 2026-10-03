# Synthetic fixture contract, version 1

This directory is a **test harness contract**, not AHP v1 or a canonical schema.
All matrices use the sole active `draft` wire revision and full `tool.before`
event envelope. Stdio scenarios with HTTP authentication are explicitly inapplicable.
See [INTERRUPTION.md](INTERRUPTION.md) for deterministic cancellation barriers and
`atomic-scenarios.json` for compound-response acceptance.

A runner reads `scenarios.json` and preserves scenario order in its report. All
successful cases submit `request` unchanged; `credential: malformed` instead
submits `{"jsonrpc":"2.0"}`. Stdio exchanges are serial on one persistent process;
HTTP exchanges may run concurrently with each other and stdio. The server uses one
no-effect implementation for all inputs. IDs and Unicode payloads are stable.

Each scenario has `id`, `transport` (`stdio`, `http`, `https`), `auth`, `credential`
(a fixture selector, never secret material) and `expected`. HTTP posts JSON to
`/<auth>`. Stdio always uses process trust, regardless of any HTTP auth palette.
HTTP credential selectors:

- `valid`: resolve the selected auth fixture; `env`: resolve `env:AHP_TEST_BEARER`
  from the adapter's explicitly injected test environment. `valid` bearer uses
  `credential:bearer` from the adapter's credential store. Neither enters JSON-RPC.
- `missing`, `invalid`: omit credentials or supply an invalid token/untrusted cert.
- OAuth `bad-client`, `missing-client`, `bad-grant`: reject the client-credentials
  token exchange. `missing-client` supplies an empty secret. The local token
  endpoint accepts form-encoded client ID/secret; it is not OAuth discovery.
- Workload `untrusted`, `issuer`, `audience`, `expired`: assert with an untrusted
  signing key, issuer, audience, or expiry respectively.
- `bearer`, `oauth`: deliberately present a token to the wrong route.
- mTLS `bad-server-ca`: do not trust the actual server's CA.

OAuth and workload fixtures use separate HS256 signing keys and purposes, local
issuer `urn:ahp:interop:local-issuer`, audience `urn:ahp:interop:local-server`, and
fixed token clock `2030-01-01T00:00:00Z`. They demonstrate cryptographic local trust,
not asymmetric workload federation or an OAuth-provider interoperability claim.
TLS uses real wall-clock certificate validation, never `rejectUnauthorized: false`.

Expected outcomes:

| Value | Required observation |
| --- | --- |
| `no-effect` | SDK-valid, ID-correlated response with `effects: []` |
| `unauthorized` | HTTP 401; no protocol handler success |
| `token-rejected` | Local token endpoint 400/401 |
| `tls-rejected` | TLS-specific verification/handshake failure; untrusted-client reset additionally requires server certificate rejection evidence |
| `invalid-request` | JSON-RPC invalid-request error (`-32600`) |
| `inapplicable` | Stdio with HTTP auth; not a passed authentication test |

The JSON report contains `format: ahp-synthetic-interop-results/1`, overall `ok`,
and ordered `results`: each has `id`, `transport`, `auth`, `expected`, `actual`,
`status` (`passed`, `failed`, `inapplicable`). Overall success additionally requires
clean server exit and clean NDJSON stdout. Failures do not expose wire data or
exception messages. Ports and TLS rejection codes travel only over IPC. No traces
contain credentials; this initial runner deliberately does not record wire traces.

Adapters in other languages may implement these test bindings and reuse the JSON,
but this initial runner launches TypeScript only. No production agent, external
issuer or LLM is involved. Requests use SDK codecs and canonical draft validation.

Subscription IDs and candidate suppliers are local harness bookkeeping, never
wire identity or authorization claims. Atomic request snapshots omit local
candidate provenance. The HTTP regression suite reuses credentials across distinct
JSON-RPC/event IDs and verifies that those IDs cannot serve as credentials.
Content tests require receiver-allocated immutable refs and confirmed descriptors;
upload authentication is independent from event authentication. Test-local input
refs are not upload request headers or expected receiver refs.
