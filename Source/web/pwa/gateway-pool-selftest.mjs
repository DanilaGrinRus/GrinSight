import assert from 'node:assert/strict';
import { startMockGateway } from './gateway-mock.mjs';
import { GatewayPool, GatewayError } from './transport.mjs';

const a = await startMockGateway({ source: 'a' });
const b = await startMockGateway({ source: 'b' });
const pool = new GatewayPool([a.url, b.url], { timeoutMs: 3000 });
try {
  const hello = await pool.request('hello', { protocol: 1 });
  assert.equal(hello.sources.length, 2);
  assert.equal(hello.sources.filter((s) => s.ok).length, 2);
  assert.deepEqual(hello.sources.map((s) => s.result.source), ['a', 'b']);

  const headers = await pool.request('headers', { from: 1, count: 1 }, { consistent: true });
  assert.deepEqual(headers.result.headers, []);

  const bad = new GatewayPool([a.url, 'ws://127.0.0.1:1'], { timeoutMs: 500 });
  const fallback = await bad.request('hello');
  assert.equal(fallback.result.protocol, 1);
  bad.close();

  await assert.rejects(pool.request('hello', {}, { consistent: true }),
    (e) => e instanceof GatewayError && e.code === 'disagreement');
  console.log('GATEWAY_POOL_SELFTEST=PASS');
} finally {
  pool.close(); await a.close(); await b.close();
}
