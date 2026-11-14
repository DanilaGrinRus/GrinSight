// Mainnet read-only header test through public peers (no local node, no keys).
// Start gateway:
//   grinsight-gateway --mainnet --bind 127.0.0.1:8787 --release-dir release \
//     --peer 107.172.238.20:3414 --peer 107.172.44.229:3414
// Then:
//   $env:GRINSIGHT_GATEWAY_URL='ws://127.0.0.1:8787'; node mainnet-chain-selftest.mjs
import assert from 'node:assert/strict';
import { GatewayClient } from './transport.mjs';
import { setNetwork, checkpointHeight, chainStart, chainAppend } from '../../web-core/browser/grinsight_api.mjs';

const url = process.env.GRINSIGHT_GATEWAY_URL || 'ws://127.0.0.1:8787';
const client = new GatewayClient(url, { timeoutMs: 30000 });
try {
  await setNetwork(1);
  assert.equal(await checkpointHeight(), 4095360);
  const start = await chainStart();
  assert.equal(start, 4095360);
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
  assert.ok(tip >= 4095360);
  console.log(`MAINNET_CHAIN_WASM_VERIFY=PASS start=${start} tip=${tip} batches=${batches}`);
} catch (e) {
  console.error('MAINNET_CHAIN_WASM_VERIFY=FAIL', e.code || '', e.message || e);
  process.exitCode = 1;
} finally {
  client.close();
  await new Promise((r) => setTimeout(r, 200));
}
