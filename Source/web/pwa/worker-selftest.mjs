import { Worker } from 'node:worker_threads';
const w = new Worker(new URL('./worker.mjs', import.meta.url));
const timeout = setTimeout(() => { console.error('WORKER_TIMEOUT'); process.exit(2); }, 60000);
w.on('message', (m) => {
  clearTimeout(timeout);
  console.log(JSON.stringify(m, null, 2));
  w.terminate();
});
w.on('error', (e) => { console.error('WORKER_ERROR', e); process.exit(1); });
w.postMessage({ id: 1, type: 'selftest' });
