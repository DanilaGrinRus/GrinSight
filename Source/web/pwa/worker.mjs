// GrinSight Web Worker: keeps the Wasm core off the UI thread.
// The browser module is the same one tested by web-core/browser/selftest.mjs.
import { abiVersion, headerHash, testAddress, testS1Length, checkpointHeight, recentHeaders, utxoFixture } from './core/grinsight_api.mjs';

const isNode = typeof process !== 'undefined' && process.versions && process.versions.node;
let nodePort = null;
if (isNode) {
  // Node worker test harness only; never used in the browser.
  ({ parentPort: nodePort } = await import('node:worker_threads'));
}

const api = {
  async selftest() {
    return {
      abi: await abiVersion(),
      headerHash: await headerHash(),
      address: await testAddress(),
      s1Length: await testS1Length(),
      checkpointHeight: await checkpointHeight(),
      recentHeaders: await recentHeaders(),
      utxoFixture: await utxoFixture(),
    };
  },
};

async function handle(data) {
  data = data || {};
  if (data.type !== 'selftest') return;
  try {
    send({ id: data.id, ok: true, result: await api.selftest() });
  } catch (err) {
    send({ id: data.id, ok: false, error: String((err && err.message) || err) });
  }
}

function send(message) {
  if (nodePort) nodePort.postMessage(message);
  else self.postMessage(message);
}

if (nodePort) nodePort.on('message', (data) => { void handle(data); });
else self.addEventListener('message', (event) => { void handle(event.data); });
