export type HookErrorCode =
  | "INVALID_CONFIG"
  | "SPAWN_ERROR"
  | "IO_ERROR"
  | "TIMEOUT"
  | "MALFORMED_UTF8"
  | "MALFORMED_JSON"
  | "MALFORMED_JSON_RPC"
  | "ID_MISMATCH"
  | "JSON_RPC_ERROR"
  | "INCOMPATIBLE_VERSION"
  | "UNSUPPORTED_EVENT"
  | "UNSUPPORTED_EFFECT"
  | "MULTIPLE_EFFECTS";

export class HookOperationalError extends Error {
  readonly code: HookErrorCode;

  constructor(code: HookErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "HookOperationalError";
    this.code = code;
  }
}
