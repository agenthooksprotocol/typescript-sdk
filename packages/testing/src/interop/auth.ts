/** TEST ONLY. Public synthetic secrets; HS256 models local trust, not production federation. */
import { createHmac, timingSafeEqual } from 'node:crypto';

const CLOCK = 1_893_456_000; // Fixed 2030-01-01T00:00:00Z, not wall-clock time.
const ISSUER = 'urn:ahp:interop:local-issuer';
const AUDIENCE = 'urn:ahp:interop:local-server';
const OAUTH_KEY = 'TEST-ONLY-ahp-interop-oauth-signing-key';
const WORKLOAD_KEY = 'TEST-ONLY-ahp-interop-workload-signing-key';
const UNTRUSTED_KEY = 'TEST-ONLY-ahp-interop-untrusted-signing-key';

function encode(value: object): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  return btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join('')).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function signature(value: string, key: string): string {
  return createHmac('sha256', key).update(value).digest('base64url');
}
function equal(left: string, right: string): boolean {
  const a = Buffer.from(left), b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
function signed(claims: object, key: string): string {
  const value = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(claims)}`;
  return `${value}.${signature(value, key)}`;
}
function valid(token: string, key: string, purpose: string): boolean {
  try {
    const parts = token.split('.');
    const [header, payload, mac] = parts;
    if (parts.length !== 3 || !header || !payload || !mac ||
        !parts.every(part => /^[A-Za-z0-9_-]+$/.test(part)) ||
        !equal(mac, signature(`${header}.${payload}`, key))) return false;
    const decode = (value: string): unknown => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0))));
    const metadata = decode(header) as Record<string, unknown> | null;
    const claims = decode(payload) as Record<string, unknown> | null;
    return metadata?.alg === 'HS256' && metadata.typ === 'JWT' &&
      claims?.iss === ISSUER && claims.aud === AUDIENCE && claims.purpose === purpose &&
      typeof claims.iat === 'number' && Number.isFinite(claims.iat) && claims.iat <= CLOCK &&
      typeof claims.exp === 'number' && Number.isFinite(claims.exp) && claims.exp > CLOCK;
  } catch { return false; }
}

export function createAuth() {
  const credentials = {
    bearer: 'TEST-ONLY-ahp-interop-static-bearer',
    clientId: 'ahp-interop-client',
    clientSecret: 'TEST-ONLY-ahp-interop-client-secret',
  };
  const claims = (purpose: string) => ({ iss: ISSUER, aud: AUDIENCE, iat: CLOCK, exp: CLOCK + 3600, purpose });
  const accessToken = signed(claims('oauth'), OAUTH_KEY);
  return {
    credentials: { ...credentials },
    authorize(path: string, headers: Record<string, string | undefined>, peerAuthorized: boolean): boolean {
      const entries = Object.entries(headers).filter(([name, value]) => name.toLowerCase() === 'authorization' && value !== undefined);
      if (path === '/none') return entries.length === 0;
      if (path === '/mtls') return peerAuthorized === true && entries.length === 0;
      if (entries.length !== 1) return false;
      const match = /^Bearer ([A-Za-z0-9_.-]+)$/i.exec(entries[0]![1]!);
      const token = match?.[1];
      if (!token) return false;
      if (path === '/bearer') return equal(token, credentials.bearer);
      if (path === '/oauth') return valid(token, OAUTH_KEY, 'oauth');
      if (path === '/workload') return valid(token, WORKLOAD_KEY, 'workload');
      return false;
    },
    token(form: URLSearchParams): { status: number; body: object } {
      if (['grant_type', 'client_id', 'client_secret'].some(name => form.getAll(name).length !== 1)) {
        return { status: 400, body: { error: 'invalid_request' } };
      }
      if (form.get('grant_type') !== 'client_credentials') {
        return { status: 400, body: { error: 'unsupported_grant_type' } };
      }
      if (!equal(form.get('client_id')!, credentials.clientId) || !equal(form.get('client_secret')!, credentials.clientSecret)) {
        return { status: 401, body: { error: 'invalid_client' } };
      }
      return { status: 200, body: { access_token: accessToken, token_type: 'Bearer', expires_in: 3600 } };
    },
    assertion(overrides: { issuer?: string; audience?: string; expired?: boolean; untrusted?: boolean } = {}): string {
      return signed({ ...claims('workload'), iss: overrides.issuer ?? ISSUER, aud: overrides.audience ?? AUDIENCE,
        exp: overrides.expired ? CLOCK - 1 : CLOCK + 3600 }, overrides.untrusted ? UNTRUSTED_KEY : WORKLOAD_KEY);
    },
  };
}
