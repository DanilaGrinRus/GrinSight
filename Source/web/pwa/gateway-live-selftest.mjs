// Loopback test against a running grinsight-gateway.
// Start the gateway first, then:
//   $env:GRINSIGHT_GATEWAY_URL='ws://127.0.0.1:8787'; node gateway-live-selftest.mjs
import assert from 'node:assert/strict';
import { GatewayClient } from './transport.mjs';

const url = process.env.GRINSIGHT_GATEWAY_URL || 'ws://127.0.0.1:8787';
const client = new GatewayClient(url, { timeoutMs: 5000 });
const timer = setTimeout(() => { console.error('GATEWAY_SELFTEST_TIMEOUT'); process.exit(3); }, 15000);

try {
  const hello = await client.request('hello', { protocol: 1, network: 'floonet' });
  assert.equal(hello.protocol, 1);
  assert.equal(hello.network, 'floonet');
  assert.deepEqual(hello.verified_by, 'browser');

  const cp = await client.request('checkpoint');
  assert.equal(cp.height, 3318854);
  assert.ok(cp.text.startsWith('RWM1\n'));

  const h = await client.request('headers', { from: 0, count: 3 });
  assert.equal(h.headers.length, 3);
  assert.ok(h.headers[0].height > 3_300_000);
  assert.equal(h.more, false);

  console.log('GATEWAY_SELFTEST=PASS checkpoint=3318854 headers=62');
  clearTimeout(timer);
  client.close();
  process.exit(0);
} catch (e) {
  console.error('GATEWAY_SELFTEST=FAIL', e.code || '', e.message || e);
  clearTimeout(timer);
  process.exit(1);
}
