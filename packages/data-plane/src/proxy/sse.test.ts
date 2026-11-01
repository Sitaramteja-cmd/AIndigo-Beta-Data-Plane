import { strict as assert } from 'node:assert';
import { Readable } from 'node:stream';
import { SSEDlpTransformStream } from './sse-transform.js';

async function runSseTests() {
  console.log('================================================================');
  console.log(' 🌊 AIndigo Tier 2 — Streaming SSE Sliding-Window DLP Test');
  console.log('================================================================');

  const chunk1 = 'data: {"choices":[{"delta":{"content":"Here is your key: AKIAIOSFOD';
  const chunk2 = 'NN7EXAMPLE use it carefully\"}}]}\\n\\n';

  const inputStream = Readable.from([chunk1, chunk2]);
  const dlpStream = new SSEDlpTransformStream(/AKIA[0-9A-Z]{16}/g);

  let outputData = '';
  for await (const chunk of inputStream.pipe(dlpStream)) {
    outputData += chunk.toString();
  }

  assert.equal(outputData.includes('AKIAIOSFODNN7EXAMPLE'), false, 'Split secret must be scrubbed');
  assert.equal(outputData.includes('[REDACTED_SECRET]'), true, 'Must contain redaction placeholder');
  console.log('✅ 1. Split-Chunk Secret Successfully Caught Across Boundary.');
  console.log('   • Output Stream Result: ' + outputData.trim());

  console.log('================================================================');
  console.log(' 🎉 Tier 2 Module 2.1 SSE Streaming Tests PASSED');
  console.log('================================================================');
}

runSseTests().catch((err) => {
  console.error('❌ SSE Test Failed:', err);
  process.exit(1);
});