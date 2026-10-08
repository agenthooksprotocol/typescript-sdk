export { hooks } from "./hooks.js";
export type {
  Message,
  Handler,
  InterceptResult,
  CapabilitiesResult,
} from "./hooks.js";
export { attachments, UploadError } from "./attachments.js";
export type { Upload } from "./attachments.js";
export type {
  ContentReference,
  ContentUploadReceipt,
  Event,
  InterceptRequest,
  ObserveNotification,
  CapabilitiesRequest,
  Effect,
} from "../draft/generated.js";

export { effects } from "../draft/generated.js";

export { effectNames, supports } from "../draft/generated.js";
export type { EffectName } from "../draft/generated.js";
