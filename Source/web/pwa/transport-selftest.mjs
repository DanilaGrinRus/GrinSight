import assert from 'node:assert/strict';
import { startMockGateway } from './gateway-mock.mjs';
import { GatewayClient, GatewayError, MAX_FRAME } from './transport.mjs';

const server = await startMockGateway();
const client = new GatewayClient(server.url, { timeoutMs: 3000 });

try {
  const hello = await client.request('hello', { protocol: 1, network: 'floonet' });
  assert.equal(hello.protocol, 1);
  assert.equal(hello.network, 'floonet');

  const headers = await client.request('headers', { from: 4095360, count: 2 });
  assert.deepEqual(headers.headers, []);
  assert.equal(headers.from, 4095360);

  await assert.rejects(
    client.request('slow', {}, { timeoutMs: 100 }),
    (e) => e instanceof GatewayError && e.code === 'timeout'
  );

  await assert.rejects(
    client.request('big'),
    (e) => e instanceof GatewayError && e.code === 'too_large'
  );

  await assert.rejects(
    client.request('unknown'),
    (e) => e instanceof GatewayError && e.code === 'unsupported'
  );

  assert.equal(MAX_FRAME, 1024 * 1024);
  console.log('TRANSPORT_SELFTEST=PASS');
} finally {
  client.close();
  await server.close();
}
