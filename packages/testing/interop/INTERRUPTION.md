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
- `timeout`: hold the response at the received barrier until the deadline
  configured in the registration expires. The public SDK owns this deadline;
  the host does not synthesize a timeout. Late effects are ignored, but the
  declared failure policy still governs execution.
- `failure`: release malformed backend output. JSON parsing rejects it;
  fail-open executes and fail-closed blocks.

The test compares exact state, traces, messages, failure counts, and execution
counts across real HTTP and stdio. Every row also runs a fresh independent
operation. Pending-interruption rows keep unrelated work in flight: on the same
HTTP server, or a separate persistent stdio backend (the binding is serial per
backend). Cancellation must not cancel that work.

Barriers and scripts use the fixture control plane only. No sleeps,
race-manufacturing polls, LLMs, external services, cancellation RPCs, or test
fields enter protocol requests. A watchdog is a test failure bound, not an
ordering mechanism. One public `Hooks` instance owns each boundary and its
ordered routes, atomic validation/composition, deadlines and cancellation.
Positive backend replies use `hooks.handle`; deliberately malformed replies
bypass it. The host accepts one SDK result and enacts its effective input and
effects, without a second staging pass. Process and socket cleanup is awaited.

This is a synthetic harness decision pipeline, not a production adapter or a
claim that already-running tools can be undone. `flow(stop/continue)` is neither
implemented nor advertised by this tool.before slice; late continuation is
explicitly **unsupported**, not counted as an accepted schema/effect test.

A focused host test resolves a real public SDK result and interrupts before its
queued host-acceptance continuation runs. This covers delivered-but-unaccepted
effects independently of transport closure. Ordered-route tests additionally
cover input/state propagation, invalidation of earlier allowances/candidates,
and interruption during the second route without dispatching the third. The
atomic matrix sends adversarial replies through public client validation.

The SDK owns persistent stdio cancellation and replacement; late bytes must not
be assigned to a new request. Client reuse is tested after interruption, and a
separate test closes a cancelled SDK-owned process without releasing its reply.
Unrelated work completes before the late response is released. HTTP cancellation
is scoped to the pending request.
