// Minimal loopback gateway for transport tests only. Not the production gateway.
// Manual WebSocket server (no `ws` dependency), text JSON frames, no TLS.
import http from 'node:http';
import crypto from 'node:crypto';

function accept(key) {
  return crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
}

function frame(text) {
  const payload = Buffer.from(text, 'utf8');
  const len = payload.length;
  let head;
  if (len < 126) {
    head = Buffer.from([0x81, len]);
  } else if (len < 65536) {
    head = Buffer.alloc(4); head[0] = 0x81; head[1] = 126; head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10); head[0] = 0x81; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([head, payload]);
}

function parseFrames(state, chunk, onText) {
  state.buf = Buffer.concat([state.buf, chunk]);
  for (;;) {
    const b = state.buf;
    if (b.length < 2) return;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
    const maskLen = masked ? 4 : 0;
    if (b.length < off + maskLen + len) return;
    const mask = masked ? b.subarray(off, off + 4) : null;
    off += maskLen;
    const payload = Buffer.from(b.subarray(off, off + len));
    if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    state.buf = b.subarray(off + len);
    if (opcode === 0x1) onText(payload.toString('utf8'));
    else if (opcode === 0x8) { state.closed = true; return; }
    else if (opcode === 0x9) { /* ping: tests do not need pong */ }
  }
}

export async function startMockGateway({ port = 0, source = 'mock-a' } = {}) {
  const server = http.createServer((req, res) => { res.writeHead(404); res.end(); });
  const clients = new Set();
  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if (!key || req.headers.upgrade?.toLowerCase() !== 'websocket') {
      socket.destroy(); return;
    }
    socket.write([
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${accept(key)}`,
      '\r\n',
    ].join('\r\n'));
    const state = { buf: Buffer.alloc(0), closed: false };
    clients.add(socket);
    socket.on('data', (chunk) => parseFrames(state, chunk, async (text) => {
      let msg; try { msg = JSON.parse(text); } catch { return; }
      if (!msg || msg.id == null) return;
      const reply = (result) => socket.write(frame(JSON.stringify({ id: msg.id, ok: true, result })));
      const fail = (code, message) => socket.write(frame(JSON.stringify({ id: msg.id, ok: false, error: { code, message } })));
      if (msg.method === 'hello') {
        reply({ protocol: 1, network: 'floonet', capabilities: ['headers', 'pibd'], peers: [], source });
      } else if (msg.method === 'headers') {
        reply({ headers: [], more: false, from: msg.params?.from ?? 0 });
      } else if (msg.method === 'slow') {
        await new Promise((r) => setTimeout(r, 500));
        reply({ delayed: true });
      } else if (msg.method === 'big') {
        reply({ payload: 'x'.repeat(1024 * 1024 + 16) });
      } else {
        fail('unsupported', `unknown method ${msg.method}`);
      }
    }));
    socket.on('close', () => { clients.delete(socket); state.closed = true; });
    socket.on('error', () => { clients.delete(socket); });
  });
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  const addr = server.address();
  return {
    url: `ws://127.0.0.1:${addr.port}`,
    close: () => new Promise((resolve) => { for (const s of clients) s.destroy(); server.close(resolve); }),
  };
}
