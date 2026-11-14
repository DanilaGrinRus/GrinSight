// End-to-end: gateway live raw headers -> browser Wasm verification.
// Start the gateway with a reachable peer first, e.g.:
//   grinsight-gateway --bind 127.0.0.1:8787 --release-dir ..\checkpoints\floonet --peer 127.0.0.1:13414
// Then:
//   $env:GRINSIGHT_GATEWAY_URL='ws://127.0.0.1:8787'; node gateway-verify-selftest.mjs
import assert from 'node:assert/strict';
import { GatewayClient } from './transport.mjs';
import { verifyHeaders } from '../../web-core/browser/grinsight_api.mjs';

const url = process.env.GRINSIGHT_GATEWAY_URL || 'ws://127.0.0.1:8787';
const client = new GatewayClient(url, { timeoutMs: 30000 });
try {
  const h = await client.request('headers', { from: 3318854, count: 5 });
  assert.equal(h.source, 'live-peer');
  assert.equal(h.headers.length, 5);
  assert.ok(h.headers[0].header && h.headers[0].header.length > 0);
  const tip = await verifyHeaders(h.headers.map((x) => x.header));
  assert.equal(tip, 3318859);
  console.log('LIVE_HEADERS_WASM_VERIFY=PASS tip=' + tip);
} catch (e) {
  console.error('LIVE_HEADERS_WASM_VERIFY=FAIL', e.code || '', e.message || e);
  process.exitCode = 1;
} finally {
  client.close();
  // Let the Emscripten runtime/WebSocket close cleanly on Windows.
  await new Promise((r) => setTimeout(r, 200));
}

