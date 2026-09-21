const CACHE = 'gnx-app-v2';
const ASSETS = ['./','./index.html','./styles.css','./app.js','./manifest.webmanifest','./icon.svg','./sw.js'];
const assetUrls = new Set(ASSETS.map(asset => new URL(asset, self.location.href).href));

self.addEventListener('install', event => event.waitUntil(
  caches.open(CACHE)
    .then(cache => cache.addAll([...assetUrls]))
    .then(() => self.skipWaiting())
));

self.addEventListener('activate', event => event.waitUntil(
  caches.keys()
    .then(keys => Promise.all(keys.filter(key => key.startsWith('gnx-app-') && key !== CACHE).map(key => caches.delete(key))))
    .then(() => self.clients.claim())
));

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  if (assetUrls.has(url.href)) {
    event.respondWith(caches.match(event.request).then(cached => cached || fetch(event.request)));
    return;
  }

  // Offline navigation falls back to the shell, but no runtime response is cached.
  if (event.request.mode === 'navigate') {
    event.respondWith(fetch(event.request).catch(() => caches.match(new URL('./index.html', self.location.href))));
  }
});
