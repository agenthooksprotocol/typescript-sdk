# Deterministic interruption fixtures

`interruption-scenarios.json` is a language-neutral test contract, not a wire
protocol extension. Run with `pnpm check` (or build, then
`node --test packages/testing/dist/test/interruption.test.js`).

Each scenario defines an ID, failure policy, response effects, and a phase:

- `pending`: wait for the server's request-received IPC barrier, interrupt the
  harness, and await local decision settlement **before** releasing the response.
  Neither fail-open nor fail-closed may execute. Late allow, return, and compound
  modify/message/return responses leave state and message sinks unchanged. The
  next subscriber is never dispatched.
- `accepted`: release the response and await the harness's pre-execution barrier.
  Interrupt there. Accepted effects and emitted messages remain; execution does
  not occur. This is not rollback.
- `timeout`: explicitly advance the synthetic harness deadline at the received
  barrier. This is a deadline callback, not a wall-clock race. The transport
  closes locally and late effects are ignored, but the declared failure policy
  still governs execution.
- `failure`: release malformed backend output. JSON parsing rejects it;
  fail-open executes and fail-closed blocks.

The test compares exact state, traces, messages, failure counts, and execution
counts across real HTTP and stdio. Every row also runs a fresh independent
operation. Pending-interruption rows keep unrelated work in flight: on the same
HTTP server, or a separate persistent stdio backend (the binding is serial per
backend). Cancellation must not cancel that work.

Barriers and scripts use child-process IPC only. No sleeps, race-manufacturing
polls, LLMs, services, cancellation RPCs, or test fields enter protocol requests.
A watchdog is a test failure bound, not an ordering mechanism. The client uses
SDK-generated codecs and canonical validation; the pipeline stages an entire
response before its sole acceptance point. Process and socket cleanup is awaited.

This is a synthetic harness decision pipeline, not a production adapter or a
claim that already-running tools can be undone. `flow(stop/continue)` is neither
implemented nor advertised by this tool.before slice; late continuation is
explicitly **unsupported**, not counted as an accepted schema/effect test.

A focused unit test also resolves a compound response and interrupts synchronously
before its queued acceptance continuation runs, under both failure policies.
This covers delivered-but-unaccepted effects independently of transport closure.
The existing atomic matrix covers schema and semantic effect-validation failures.

Persistent stdio detaches the canceled waiter immediately and quarantines its
framing slot until the late frame drains; it never assigns late bytes to the next
request. Reuse after draining is tested in every row. If a backend never replies,
dispose it and start a replacement: a separate test proves this path works without
releasing the abandoned response. Unrelated work completes before the late
response is released. HTTP abort destroys only the pending request.
