const CACHE = 'gnx-app-v4';
const ASSETS = ['./','./index.html','./styles.css','./app.js','./manifest.webmanifest','./icon.svg'];
const assetUrls = new Set(ASSETS.map(asset => new URL(asset, self.location.href).href));

self.addEventListener('install', event => event.waitUntil(
  caches.open(CACHE)
    .then(cache => cache.addAll(ASSETS.map(asset => new Request(asset, { cache: 'reload' }))))
    .then(() => self.skipWaiting())
));

self.addEventListener('activate', event => event.waitUntil(
  caches.keys()
    .then(keys => Promise.all(keys.filter(key => key.startsWith('gnx-app-') && key !== CACHE).map(key => caches.delete(key))))
    .then(() => self.clients.claim())
));

async function networkFirst(request, fallback) {
  try {
    const response = await fetch(request, { cache: 'no-store' });
    if (response.ok) {
      const cache = await caches.open(CACHE);
      await cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    const cached = await caches.match(request) || (fallback && await caches.match(fallback));
    if (cached) return cached;
    throw error;
  }
}

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  if (event.request.mode === 'navigate') {
    event.respondWith(networkFirst(event.request, new URL('./index.html', self.location.href)));
    return;
  }
  if (assetUrls.has(url.href)) event.respondWith(networkFirst(event.request));
});
