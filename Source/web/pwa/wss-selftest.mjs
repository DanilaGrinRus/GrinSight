// WSS smoke test through the TLS reverse proxy. Use a real trust store in
// production; for the self-signed test cert run Node with
// NODE_TLS_REJECT_UNAUTHORIZED=0 (test only).
//   $env:GRINSIGHT_GATEWAY_URL='wss://127.0.0.1:9443'; node wss-selftest.mjs
import assert from 'node:assert/strict';
import { GatewayClient } from './transport.mjs';

const url = process.env.GRINSIGHT_GATEWAY_URL || 'wss://127.0.0.1:9443';
const client = new GatewayClient(url, { timeoutMs: 8000 });
try {
  const hello = await client.request('hello', { protocol: 1 });
  assert.equal(hello.network, 'floonet');
  assert.equal(hello.verified_by, 'browser');
  const cp = await client.request('checkpoint');
  assert.equal(cp.height, 3318854);
  console.log('WSS_SELFTEST=PASS checkpoint=3318854');
} catch (e) {
  console.error('WSS_SELFTEST=FAIL', e.code || '', e.message || e);
  process.exitCode = 1;
} finally {
  client.close();
  await new Promise((r) => setTimeout(r, 200));
}
