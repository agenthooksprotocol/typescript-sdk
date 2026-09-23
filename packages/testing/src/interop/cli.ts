import { runInterop } from './client.js';
try {
  const result = await runInterop();
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  if (!result.ok) process.exitCode = 1;
} catch {
  process.stderr.write('Synthetic interoperability harness failed (details suppressed to protect credentials).\n');
  process.exitCode = 1;
}
