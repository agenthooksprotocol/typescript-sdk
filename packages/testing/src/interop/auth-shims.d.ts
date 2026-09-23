/* Narrow additions to the dependency-free Node crypto shim. */
declare module 'node:crypto' {
  export function createHmac(algorithm: string, key: string): {
    update(value: string): { digest(encoding: 'base64url'): string };
  };
  export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
}
