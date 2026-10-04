/** Harness-facing, configuration-driven API for the complete canonical draft catalogue. */
export { Hooks } from "./hooks.js";
export * from "./types.js";
export * from "./auth.js";
export * from "./content.js";
export * from "./composition.js";
export * from "./transport.js";
export type {
  Registration,
  Capabilities,
  StaticCapabilityManifest,
  Effect,
  InterceptResponse,
  Authentication,
  ContentSelection,
  ContentUpload,
} from "../draft/generated.js";
