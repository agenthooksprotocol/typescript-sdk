import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { skipFor } from './fixtures/sdk-features.mjs';

const root = new URL('../../../', import.meta.url);
const vendored = readFileSync(new URL('../testdata/sdk-auth-lifecycle.json', import.meta.url));
const vectors = JSON.parse(vendored.toString('utf8'));
const lock = JSON.parse(readFileSync(new URL('src/draft/ahp-codegen.lock.json', new URL('../', import.meta.url)), 'utf8'));

test('vendored lifecycle fixture is byte-identical to the canonical file at the pinned protocol ref', () => {
  // The lock's sourceCommit is the protocol ref the sources were generated from:
  // the SDK's own CI pin, or the protocol head in protocol-side integration runs.
  const pin = lock.sourceCommit;
  const canonical = execFileSync('git', ['-C', new URL('../agent-hooks-protocol', root).pathname, 'show', `${pin}:conformance/draft/sdk-auth-lifecycle.json`]);
  assert.ok(Buffer.compare(vendored, canonical) === 0, 'vendored fixture differs from the pinned canonical file');
  const sha = createHash('sha256').update(vendored).digest('hex');
  assert.match(readFileSync(new URL('../testdata/README.md', import.meta.url), 'utf8'), new RegExp(sha));
});

// The mapping lives here: each lifecycle id is the leading [tag] of a native test title.
const testFiles = readdirSync(new URL('.', import.meta.url)).filter(name => name.endsWith('.test.mjs'));
const tagged = new Map();
for (const name of testFiles) {
  const source = readFileSync(new URL(name, import.meta.url), 'utf8');
  for (const [, id] of source.matchAll(/\btest\(\s*['"`]\[([a-z0-9-]+)\]/g)) tagged.set(id, [...(tagged.get(id) ?? []), name]);
}
test('every fixture lifecycle id maps to an existing native test', () => {
  // An entry requiring a feature this SDK lacks applies to other SDKs only.
  const missing = vectors.lifecycle.filter(entry => !skipFor(entry)).map(entry => entry.id).filter(id => !tagged.has(id));
  assert.deepEqual(missing, []);
});
