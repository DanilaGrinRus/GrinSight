// Auto-discovery smoke test: no --peer, gateway found PIBD peers by DNS seeds.
//   grinsight-gateway --mainnet --release-dir release
//   $env:GRINSIGHT_GATEWAY_URL='ws://127.0.0.1:8787'; node gateway-auto-selftest.mjs
import assert from 'node:assert/strict';
import { GatewayClient } from './transport.mjs';

const url = process.env.GRINSIGHT_GATEWAY_URL || 'ws://127.0.0.1:8787';
const client = new GatewayClient(url, { timeoutMs: 90000 });
try {
  const peers = await client.request('peers');
  assert.ok(Array.isArray(peers.peers) && peers.peers.length >= 1, 'no auto-discovered peers');
  const cp = await client.request('checkpoint');
  assert.equal(cp.height, 4095360);
  const h = await client.request('headers', { from: 4095360, count: 3 });
  assert.equal(h.source, 'live-peer');
  assert.ok(h.headers.length >= 1);
  console.log(`GATEWAY_AUTO_SELFTEST=PASS peers=${peers.peers.length} first=${peers.peers[0]} headers=${h.headers.length}`);
} catch (e) {
  console.error('GATEWAY_AUTO_SELFTEST=FAIL', e.code || '', e.message || e);
  process.exitCode = 1;
} finally {
  client.close();
  await new Promise((r) => setTimeout(r, 200));
}

