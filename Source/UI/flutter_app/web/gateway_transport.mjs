// Browser transport for the GrinSight WSS gateway contract.
// No keys, no verification: the browser core must verify every payload.
//
// Frame: UTF-8 JSON. Request: {id, method, params}. Response: {id, ok, result}
// or {id, ok:false, error:{code,message}}. Events: {event, ...} with no id.

export const PROTOCOL = 1;
export const MAX_FRAME = 1024 * 1024;
export const DEFAULT_TIMEOUT_MS = 20_000;

export class GatewayError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'GatewayError';
    this.code = code;
  }
}

export class GatewayClient {
  constructor(url, { timeoutMs = DEFAULT_TIMEOUT_MS, maxFrame = MAX_FRAME } = {}) {
    this.url = url;
    this.timeoutMs = timeoutMs;
    this.maxFrame = maxFrame;
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
  }

  connect() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.url);
      this.ws = ws;
      ws.onopen = () => resolve();
      ws.onerror = () => reject(new GatewayError('transport', 'websocket error'));
      ws.onclose = () => {
        for (const [id, p] of this.pending) {
          clearTimeout(p.timer);
          p.reject(new GatewayError('closed', `gateway closed (request ${id})`));
        }
        this.pending.clear();
      };
      ws.onmessage = (event) => {
        if (typeof event.data !== 'string') return;
        if (event.data.length > this.maxFrame) {
          for (const p of this.pending.values()) {
            clearTimeout(p.timer);
            p.reject(new GatewayError('too_large', 'gateway frame exceeds limit'));
          }
          this.pending.clear();
          return;
        }
        let msg;
        try { msg = JSON.parse(event.data); } catch { return; }
        if (msg && msg.id != null && this.pending.has(msg.id)) {
          const p = this.pending.get(msg.id);
          this.pending.delete(msg.id);
          clearTimeout(p.timer);
          if (msg.ok) p.resolve(msg.result);
          else p.reject(new GatewayError(msg.error?.code || 'gateway', msg.error?.message || 'gateway error'));
        } else if (msg && msg.event) {
          this.events.push(msg);
          if (this.events.length > 64) this.events.shift();
        }
      };
    });
  }

  async request(method, params = {}, { timeoutMs = this.timeoutMs } = {}) {
    await this.connect();
    const id = this.nextId++;
    const payload = JSON.stringify({ id, method, params });
    if (payload.length > this.maxFrame) throw new GatewayError('too_large', 'request exceeds max frame');
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new GatewayError('timeout', `gateway timeout (${method})`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.ws.send(payload);
    });
  }

  close() {
    if (this.ws) this.ws.close();
    this.ws = null;
  }
}

/// Query several gateways independently. The caller sees every source and any
/// disagreement; no majority is trusted automatically.
export class GatewayPool {
  constructor(urls, opts = {}) {
    this.clients = urls.map((url) => ({ url, client: new GatewayClient(url, opts) }));
  }

  async query(method, params = {}) {
    const out = [];
    await Promise.all(this.clients.map(async ({ url, client }) => {
      try {
        out.push({ url, ok: true, result: await client.request(method, params) });
      } catch (e) {
        out.push({ url, ok: false, code: e.code || 'error', error: e.message || String(e) });
      }
    }));
    out.sort((a, b) => a.url.localeCompare(b.url));
    return out;
  }

  /// First successful answer plus all sources. `consistent` re-queries and
  /// rejects if successful payloads differ; it does not prove correctness.
  async request(method, params = {}, { consistent = false } = {}) {
    const results = await this.query(method, params);
    const good = results.filter((r) => r.ok);
    if (!good.length) throw new GatewayError('unavailable', 'no gateway answered');
    if (consistent) {
      const canon = good.map((r) => JSON.stringify(r.result));
      if (new Set(canon).size !== 1) throw new GatewayError('disagreement', 'gateways disagree');
    }
    return { result: good[0].result, sources: results };
  }

  close() { for (const { client } of this.clients) client.close(); }
}
