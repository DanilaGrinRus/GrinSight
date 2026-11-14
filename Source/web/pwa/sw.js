// Offline shell for the diagnostic PWA. CACHE is rewritten by build_pwa.ps1
// (hash of UI + core): any rebuild gives a new service worker and a new cache.
const CACHE = 'grinsight-pwa-v1';
const ASSETS = [
  './',
  './index.html',
  './manifest.webmanifest',
  './worker.mjs',
  './core/grinsight_api.mjs',
  './core/grinsight_core.js',
  './core/grinsight_core.wasm',
  './icons/Icon-192.png',
  './icons/Icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE)
    // Fetch past the HTTP cache: a new version must not store old files.
    .then((cache) => cache.addAll(ASSETS.map((u) => new Request(u, { cache: 'reload' }))))
    .then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request).then((response) => {
      if (response.ok && new URL(event.request.url).origin === self.location.origin) {
        const copy = response.clone();
        caches.open(CACHE).then((cache) => cache.put(event.request, copy)).catch(() => {});
      }
      return response;
    }).catch(() => caches.match('./index.html')))
  );
});
