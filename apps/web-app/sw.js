const CACHE = 'gnx-app-v1';
const ASSETS = ['./','./index.html','./styles.css','./app.js','./manifest.webmanifest','./icon.svg'];
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(ASSETS)).then(() => self.skipWaiting())));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', event => { const url = new URL(event.request.url); if (url.origin !== self.location.origin) return; event.respondWith(caches.match(event.request).then(cached => cached || fetch(event.request))); });
