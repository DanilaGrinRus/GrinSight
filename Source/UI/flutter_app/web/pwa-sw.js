// GrinSight PWA offline shell. The generated Flutter service worker only
// unregisters itself, so the app registers this cache explicitly.
const CACHE = 'grinsight-pwa-v8';
const ASSETS = [
  './',
  'index.html',
  'manifest.json',
  'flutter_bootstrap.js',
  'main.dart.js',
  'backend_web_bridge.mjs',
  'gateway_transport.mjs',
  'gateway_bundle_sync.mjs',
  'core/grinsight_api.mjs',
  'core/grinsight_core.js',
  'core/grinsight_core.wasm',
  'flutter.js',
  'canvaskit/canvaskit.js',
  'canvaskit/canvaskit.wasm',
  'assets/FontManifest.json',
  'assets/AssetManifest.bin',
  'assets/fonts/MaterialIcons-Regular.otf',
  'assets/packages/cupertino_icons/assets/CupertinoIcons.ttf',
  'assets/assets/icon/app_mark.png',
  'assets/assets/checkpoints/mainnet/checkpoint.rwm',
  'assets/assets/checkpoints/mainnet/recent-headers.bin',
  'assets/assets/checkpoints/mainnet/release.sig',
  'assets/assets/checkpoints/mainnet/release.txt',
  'assets/assets/checkpoints/floonet/checkpoint.rwm',
  'assets/assets/checkpoints/floonet/recent-headers.bin',
  'assets/assets/checkpoints/floonet/pin.txt',
  'assets/shaders/ink_sparkle.frag',
  'assets/shaders/stretch_effect.frag',
  'version.json',
  'icons/Icon-192.png',
  'icons/Icon-512.png',
  'favicon.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  event.respondWith(
    caches.match(req).then((hit) => {
      if (hit) return hit;
      return fetch(req).then((res) => {
        if (res.ok && new URL(req.url).origin === self.location.origin) {
          const copy = res.clone();
          caches.open(CACHE).then((cache) => cache.put(req, copy));
        }
        return res;
      }).catch(() => caches.match('index.html'));
    }),
  );
});







