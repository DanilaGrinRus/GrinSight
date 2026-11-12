// Full live Floonet header chain: gateway -> browser transport -> Wasm stateful verifier.
// Start gateway with a live Floonet peer first:
//   grinsight-gateway --bind 127.0.0.1:8787 --release-dir ..\checkpoints\floonet --peer IP:PORT
// Then:
//   $env:GRINSIGHT_GATEWAY_URL='ws://127.0.0.1:8787'; node gateway-chain-selftest.mjs
import assert from 'node:assert/strict';
import { GatewayClient } from './transport.mjs';
import { chainStart, chainAppend, chainTip } from '../../web-core/browser/grinsight_api.mjs';

const url = process.env.GRINSIGHT_GATEWAY_URL || 'ws://127.0.0.1:8787';
const client = new GatewayClient(url, { timeoutMs: 30000 });
try {
  const start = await chainStart();
  assert.equal(start, 3318854);
  let tip = start;
  let locator = null;
  let batches = 0;
  for (let i = 0; i < 60; i++) {
    const params = { from: tip, count: 512 };
    if (locator) params.locator = locator;
    const h = await client.request('headers', params);
    if (!h.headers.length) break;
    tip = await chainAppend(h.headers.map((x) => x.header));
    locator = h.headers[h.headers.length - 1].hash;
    batches++;
    if (h.headers.length < 512) break;
  }
  assert.equal(await chainTip(), tip);
  assert.ok(tip >= 3_333_000, `tip ${tip} too low`);
  console.log(`LIVE_CHAIN_WASM_VERIFY=PASS start=${start} tip=${tip} batches=${batches}`);
} catch (e) {
  console.error('LIVE_CHAIN_WASM_VERIFY=FAIL', e.code || '', e.message || e);
  process.exitCode = 1;
} finally {
  client.close();
  await new Promise((r) => setTimeout(r, 200));
}
