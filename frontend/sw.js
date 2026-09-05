const CACHE_NAME = 'bchat-v6';
const ASSETS = [
    '/index.html',
    '/go.css',
    '/app.js',
    '/logo.svg',
    '/icons.svg',
    '/icon-192.png',
    '/icon-512.png',
    '/manifest.json',
    '/admin.html',
    '/robots.txt',
    '/sitemap.xml',
    '/googlee6f3ef6166a4f027.html'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
        )
    );
    self.clients.claim();
});

self.addEventListener('fetch', (event) => {
    if (event.request.url.includes('googleapis') || event.request.url.includes('pollinations')) {
        event.respondWith(fetch(event.request));
        return;
    }
    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
});
