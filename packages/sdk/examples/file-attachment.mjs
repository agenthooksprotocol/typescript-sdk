// Run: node packages/sdk/examples/file-attachment.mjs ./hooks.json ./policy.txt
import { readFile, open } from 'node:fs/promises';
import { Attachment, Hooks, contentSlots } from 'agenthooksprotocol/client';

const [configPath, policyPath] = process.argv.slice(2);
if (!configPath || !policyPath) throw Error('Expected hooks.json and policy file paths');
const hooks = new Hooks(JSON.parse(await readFile(configPath, 'utf8')), {
  source: 'urn:example:document-agent',
  maxContentBytes: 4 * 1024 * 1024,
  capabilities: { 'context.compact.before': { modes: ['intercept'], capabilities: { effects: ['deny'] } } },
});
let result;
try {
  // No file descriptor is opened until a selected consumer or result reader asks.
  const policy = Attachment.lazy(async signal => {
    signal.throwIfAborted();
    const file = await open(policyPath, 'r');
    try {
      if ((await file.stat()).size > 4 * 1024 * 1024) throw Error('Policy file too large');
      return await file.readFile({ signal });
    } finally { await file.close(); }
  });
  result = await hooks.contextCompactBefore({
    trigger: 'manual', items: [],
    instructions: { id: 'policy', kind: 'text', mediaType: 'text/plain' },
  }, { contentSources: [contentSlots['context.compact.before'].instructions(policy)] });
  await hooks.close();
  if (result.interrupted || result.permission === 'deny') throw Error('Compaction not permitted');
  // Local effective content remains readable after transport shutdown.
  console.log(new TextDecoder().decode(await result.content.read('policy')));
} finally {
  try { await result?.content?.close(); }
  finally { await hooks.close(); }
}
