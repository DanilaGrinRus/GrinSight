// Fetch a precomputed GPF1 bundle from the gateway by chunks.
import { GatewayClient } from './gateway_transport.mjs';

export async function fetchGatewayBundle(url, onProgress) {
  let client = new GatewayClient(url, { timeoutMs: 120000 });
  let info;
  try {
    info = await client.request('bundle_info', {});
  } catch (e) {
    client.close();
    throw e;
  }
  if (!info || !info.ready || !info.size) {
    client.close();
    throw new Error('gateway has no bundle');
  }
  const size = info.size;
  const chunk = 262144;
  const out = new Uint8Array(size);
  let offset = 0;
  let count = 0;
  try {
    while (offset < size) {
      if (count > 0 && count % 100 === 0) {
        client.close();
        client = new GatewayClient(url, { timeoutMs: 120000 });
      }
      const want = Math.min(chunk, size - offset);
      const r = await client.request('pibd_chunk', { offset, length: want });
      const bytes = r.data.match(/.{2}/g).map((x) => parseInt(x, 16));
      if (bytes.length !== r.length) throw new Error('bad chunk');
      out.set(bytes, offset);
      offset += bytes.length;
      count++;
      if (onProgress && offset % (10 * 1024 * 1024) < chunk) onProgress(offset, size);
    }
    return out;
  } finally {
    client.close();
  }
}
