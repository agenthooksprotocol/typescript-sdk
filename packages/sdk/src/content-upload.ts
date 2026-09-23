/** Normative HTTP content upload. Event authentication is deliberately not an input. */
export interface UploadConfiguration {
  endpoint: string;
  auth?: {type: 'bearer'; tokenEnv: string; [key: string]: unknown};
  timeoutMs?: number;
  maxBytes?: number;
  [key: string]: unknown;
}
export interface BodyReference {ref: string; size: number; sha256: string}
/** Check the receiver descriptor before exposing a body reference. */
export function validateBodyReference(value: unknown, size: number, sha256: string): BodyReference {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid upload descriptor');
  const body = value as Record<string, unknown>;
  if (Object.keys(body).some(key => !['ref', 'size', 'sha256'].includes(key)) ||
      typeof body.ref !== 'string' || !body.ref || !Number.isSafeInteger(body.size) ||
      body.size !== size || typeof body.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(body.sha256) || body.sha256 !== sha256) throw Error('Unconfirmed bytes');
  return {ref: body.ref, size, sha256};
}
export async function uploadContent(config: UploadConfiguration, bytes: Uint8Array, options: {resolveToken?: (name: string) => string | undefined; allowLoopback?: boolean} = {}): Promise<BodyReference> {
  if (!config || typeof config.endpoint !== 'string' ||
      (config.timeoutMs !== undefined && (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs <= 0)) ||
      (config.maxBytes !== undefined && (!Number.isSafeInteger(config.maxBytes) || config.maxBytes < 0))) throw Error('Invalid upload configuration');
  const url = new URL(config.endpoint);
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' && !(options.allowLoopback && url.protocol === 'http:' && ['127.0.0.1','localhost','[::1]'].includes(url.hostname)))) throw Error('Unsafe upload endpoint');
  if (!(bytes instanceof Uint8Array)) throw Error('Invalid content bytes');
  const snapshot = new Uint8Array(bytes);
  if (snapshot.length > (config.maxBytes ?? 52428800)) throw Error('Upload size limit');
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', snapshot));
  const sha256 = Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('');
  const headers: Record<string, string> = {'content-type':'application/octet-stream','content-length':String(snapshot.length),'ahp-content-sha256':sha256};
  if (config.auth !== undefined) {
    if (!config.auth || config.auth.type !== 'bearer' || typeof config.auth.tokenEnv !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(config.auth.tokenEnv)) throw Error('Invalid upload authentication');
    const token = options.resolveToken?.(config.auth.tokenEnv);
    if (typeof token !== 'string' || !token) throw Error('Missing upload credential');
    headers.authorization = `Bearer ${token}`;
  }
  const response = await fetch(url, {method:'POST',headers,body:snapshot,redirect:'error',signal:AbortSignal.timeout(config.timeoutMs ?? 15000)});
  if (response.status !== 201 || response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
    await response.body?.cancel();
    throw Error(`Content upload failed: HTTP ${response.status}`);
  }
  return validateBodyReference(await response.json(), snapshot.length, sha256);
}
export interface NormalizedContentInput {
  id: string; kind: string; mediaType: string; ref?: string; bytes?: Uint8Array;
  category?: string; role?: string; parentItemId?: string; synthesized?: boolean;
}
export interface NormalizedContentView {
  id: string; kind: string; mediaType: string; category?: string; role?: string; parentItemId?: string; synthesized?: boolean;
  selection: 'body' | 'metadata' | 'omit'; body?: BodyReference; gap?: {reason: string};
}
/** Select once per subscriber. Return no body reference until upload confirms availability. */
export async function prepareWireContent(items: readonly NormalizedContentInput[], options: {
  subscription?: string; selection: Record<string, 'body' | 'metadata' | 'omit'>;
  authorized: (item: NormalizedContentInput) => boolean;
  upload: (bytes: Uint8Array) => Promise<BodyReference>;
  mode: 'intercept' | 'observe'; failClosed: boolean; timeoutMs?: number; maxBytes?: number;
}): Promise<NormalizedContentView[]> {
  const result: NormalizedContentView[] = [];
  for (const item of items) {
    const {id,kind,mediaType,category,role,parentItemId,synthesized} = item;
    const view: NormalizedContentView = {id,kind,mediaType, ...(synthesized === undefined ? {} : {synthesized}), ...(category ? {category} : {}), ...(role ? {role} : {}), ...(parentItemId ? {parentItemId} : {}), selection:options.selection[category ?? kind] ?? options.selection.default ?? 'metadata'};
    if (view.selection === 'body') {
      if (!options.authorized(item)) view.gap = {reason:'permission_withheld'};
      else if (item.bytes === undefined) view.gap = {reason:'source_unavailable'};
      else if (item.bytes.length > (options.maxBytes ?? 52428800)) view.gap = {reason:'limit_exceeded'};
      else try {
        const bytes = new Uint8Array(item.bytes);
        let timer: ReturnType<typeof setTimeout> | undefined;
        let body: BodyReference;
        try {
          body = await Promise.race([options.upload(bytes.slice()), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(Error('Upload timeout')), options.timeoutMs ?? 15000); })]);
        } finally { if (timer !== undefined) clearTimeout(timer); }
        const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2,'0')).join('');
        view.body = validateBodyReference(body, bytes.length, hash);
      } catch { view.gap = {reason:'transfer_failed'}; }
      if (view.gap && options.mode === 'intercept' && options.failClosed) throw Error(`Content delivery failure: ${view.gap.reason}`);
    }
    result.push(view);
  }
  return result;
}
