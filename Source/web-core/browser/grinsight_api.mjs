// Thin ES-module API for the Flutter Web / Web Worker bridge.
// The generated grinsight_core.js/wasm are build artifacts of build_browser.ps1.

import createGrinSightCore from './grinsight_core.js';

let _module;

export async function loadCore() {
  if (!_module) _module = await createGrinSightCore();
  return _module;
}

function readBytes(mod, ptr, len) {
  return mod.HEAPU8.slice(ptr, ptr + len);
}

export async function abiVersion() {
  const mod = await loadCore();
  return mod._gs_abi_version();
}

export async function headerHash() {
  const mod = await loadCore();
  const ptr = mod._malloc(32);
  try {
    const n = mod._gs_header_hash(ptr, 32);
    return Array.from(readBytes(mod, ptr, n)).map((b) => b.toString(16).padStart(2, '0')).join('');
  } finally {
    mod._free(ptr);
  }
}

export async function testAddress() {
  const mod = await loadCore();
  const ptr = mod._malloc(128);
  try {
    const n = mod._gs_test_address(ptr, 128);
    return new TextDecoder().decode(readBytes(mod, ptr, n));
  } finally {
    mod._free(ptr);
  }
}

export async function testS1Length() {
  const mod = await loadCore();
  const ptr = mod._malloc(8192);
  try {
    return mod._gs_test_s1(ptr, 8192);
  } finally {
    mod._free(ptr);
  }
}

export async function checkpointHeight() {
  const mod = await loadCore();
  // Emscripten returns i64 as BigInt; heights are < 2^53.
  return Number(mod._gs_checkpoint_height());
}

export async function recentHeaders() {
  const mod = await loadCore();
  return Number(mod._gs_restore_recent());
}

export async function storageSelftest() {
  const mod = await loadCore();
  const ptr = mod._malloc(128);
  try {
    const n = mod._gs_storage_selftest(ptr, 128);
    if (n < 0) return { ok: false, code: n };
    return { ok: true, value: new TextDecoder().decode(readBytes(mod, ptr, n)) };
  } finally {
    mod._free(ptr);
  }
}

/// headerHexes: hex strings from gateway. Builds recent-headers.bin-shaped
/// packet and lets the Wasm verifier append them to the Floonet checkpoint.
export async function verifyHeaders(headerHexes) {
  const mod = await loadCore();
  const raw = headerHexes.map((h) => {
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
    return out;
  });
  let total = 4;
  for (const b of raw) total += 4 + b.length;
  const packet = new Uint8Array(total);
  const view = new DataView(packet.buffer);
  view.setUint32(0, raw.length, true);
  let off = 4;
  for (const b of raw) {
    view.setUint32(off, b.length, true); off += 4;
    packet.set(b, off); off += b.length;
  }
  const ptr = mod._malloc(packet.length);
  try {
    mod.HEAPU8.set(packet, ptr);
    const h = mod._gs_verify_headers(ptr, packet.length);
    return Number(h);
  } finally {
    mod._free(ptr);
  }
}

function packetFromHexes(headerHexes) {
  const raw = headerHexes.map((h) => {
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
    return out;
  });
  let total = 4;
  for (const b of raw) total += 4 + b.length;
  const packet = new Uint8Array(total);
  const view = new DataView(packet.buffer);
  view.setUint32(0, raw.length, true);
  let off = 4;
  for (const b of raw) {
    view.setUint32(off, b.length, true); off += 4;
    packet.set(b, off); off += b.length;
  }
  return packet;
}

export async function chainStart() {
  const mod = await loadCore();
  return Number(mod._gs_chain_start());
}

export async function chainAppend(headerHexes) {
  const mod = await loadCore();
  const packet = packetFromHexes(headerHexes);
  const ptr = mod._malloc(packet.length);
  try {
    mod.HEAPU8.set(packet, ptr);
    return Number(mod._gs_chain_append(ptr, packet.length));
  } finally {
    mod._free(ptr);
  }
}

export async function chainTip() {
  const mod = await loadCore();
  return Number(mod._gs_chain_tip());
}

export async function utxoFixture() {
  const mod = await loadCore();
  return Number(mod._gs_utxo_fixture());
}

export async function chainHeader(height) {
  const mod = await loadCore();
  const ptr = mod._malloc(4096);
  try {
    const n = mod._gs_chain_header(BigInt(height), ptr, 4096);
    if (n < 0) return null;
    return Array.from(readBytes(mod, ptr, n)).map((b) => b.toString(16).padStart(2, '0')).join('');
  } finally {
    mod._free(ptr);
  }
}


/// mainnet=1, Floonet=0. Must be called before checkpoint/chain helpers.
export async function setNetwork(mainnet) {
  const mod = await loadCore();
  return mod._gs_set_network(mainnet ? 1 : 0);
}

export async function chainHeaderHash(height) {
  const mod = await loadCore();
  const ptr = mod._malloc(32);
  try {
    const n = mod._gs_chain_header_hash(BigInt(height), ptr, 32);
    if (n !== 32) return null;
    return Array.from(readBytes(mod, ptr, n)).map((b) => b.toString(16).padStart(2, '0')).join('');
  } finally {
    mod._free(ptr);
  }
}
