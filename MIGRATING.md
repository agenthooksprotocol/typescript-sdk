# Migrating

## Unreleased (0.5 → next)

Every event now has its own generated host capability declaration type,
following agent-hooks-protocol#35.

| 0.5 API                                                         | Replacement                                                                                                       |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `CapabilityObservation` (`agenthooksprotocol/client`, `/draft`) | The event's own `<Event>HostCapabilities` type, e.g. `SessionEndHostCapabilities` or `ToolBeforeHostCapabilities` |
| `observe: true` was required on entries without `intercept`     | `observe` is an optional `boolean`; `{}` and `{ observe: false }` are valid and grant nothing                     |

Declarations written as `satisfies HostCapabilities` keep compiling unchanged:

```ts
import type {
  HostCapabilities,
  SessionEndHostCapabilities,
} from "agenthooksprotocol/client";

const sessionEnd: SessionEndHostCapabilities = { observe: true };
const capabilities = {
  sessionEnd,
  toolBefore: { intercept: { deny: true }, observe: true },
} satisfies HostCapabilities;
```
