// Node 20 incremental hashing, kept local to the server implementation.
declare module "node:crypto" {
  export function createHash(algorithm: "sha256"): {
    update(data: Uint8Array): unknown;
    digest(encoding: "hex"): string;
  };
}
