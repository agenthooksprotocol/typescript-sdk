# Draft entrypoint

`@agenthooksprotocol/sdk/draft` provides generated models and codecs for the
canonical draft catalogue, schema-backed validators, and reference runtime
helpers. It is separate from the root deny/no-effect `tool.before` stdio runner;
generated catalogue coverage is not full runtime support.

See the [draft API guide](../../DRAFT-API.md) for validation, local versus wire
identity, receiver-allocated content uploads, preparation callbacks, and runtime
limits. `draftCodecs` is permissive decoding, not authorization validation.

Protocol authority lives in the sibling repository's
[`spec/draft`](../../../../../agent-hooks-protocol/spec/draft/index.md) and
[`schema/draft`](../../../../../agent-hooks-protocol/schema/draft/manifest.json).
Generated files in this directory must be regenerated from that source, not
edited to define a different protocol contract.
