// Optional SDK features a shared vector may name in `requires` (spec: Executable coverage).
// A vector applies only when this SDK has every feature it requires; otherwise it is
// skipped, never remapped onto another mechanism. An unknown feature fails the suite.
export const KNOWN_FEATURES = Object.freeze(['complete_handle', 'token_validation_callback']);
/** TypeScript: complete() takes no pending-login handle, and managedOAuth has no token-validation callback. */
export const SDK_FEATURES = Object.freeze([]);

/** False when the vector applies; otherwise the skip reason. Throws on an unknown feature. */
export function skipFor(vector) {
  const requires = vector.requires ?? [];
  const unknown = requires.filter(feature => !KNOWN_FEATURES.includes(feature));
  if (unknown.length) throw new Error(`vector ${vector.id} requires unknown SDK features: ${unknown.join(', ')}`);
  const missing = requires.filter(feature => !SDK_FEATURES.includes(feature));
  return missing.length ? `requires ${missing.join(', ')}, which this SDK does not have` : false;
}
