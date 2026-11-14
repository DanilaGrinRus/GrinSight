import { abiVersion, headerHash, testAddress, testS1Length, checkpointHeight, recentHeaders, storageSelftest, utxoFixture } from './grinsight_api.mjs';
if (typeof localStorage === 'undefined') {
  const m = new Map();
  globalThis.localStorage = {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
}
console.log('ABI=' + await abiVersion());
console.log('HEADER_HASH=' + await headerHash());
console.log('ADDRESS=' + await testAddress());
console.log('S1_LEN=' + await testS1Length());
console.log('CHECKPOINT_HEIGHT=' + await checkpointHeight());
console.log('RECENT_HEADERS=' + await recentHeaders());
console.log('STORAGE=' + JSON.stringify(await storageSelftest()));
console.log('UTXO_FIXTURE=' + await utxoFixture());
