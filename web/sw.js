/**
 * CHRONOS Service Worker
 * Enables offline support, caching, and instant loading.
 */

const CACHE_NAME = 'chronos-v1';
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/style.css',
    '/script.js',
    'https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js',
    'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js',
    'https://cdn.jsdelivr.net/npm/chart.js',
    'https://cdn.socket.io/4.7.4/socket.io.min.js'
];

// Install - cache static assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            console.log('📦 Caching static assets');
            return cache.addAll(STATIC_ASSETS);
        })
    );
    self.skipWaiting();
});

// Activate - clean old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter((key) => key !== CACHE_NAME)
                    .map((key) => caches.delete(key))
            );
        })
    );
    self.clients.claim();
});

// Fetch - serve from cache, fallback to network
self.addEventListener('fetch', (event) => {
    const { request } = event;
    const url = new URL(request.url);

    // API calls - network first, no cache
    if (url.pathname.startsWith('/api/')) {
        event.respondWith(
            fetch(request)
                .catch(() => new Response(JSON.stringify({ error: 'offline' }), {
                    headers: { 'Content-Type': 'application/json' }
                }))
        );
        return;
    }

    // Socket.IO - skip
    if (url.pathname.startsWith('/socket.io')) {
        return;
    }

    // Static assets - cache first
    event.respondWith(
        caches.match(request).then((cached) => {
            if (cached) {
                // Return cached, update in background
                fetch(request).then((response) => {
                    if (response.ok) {
                        caches.open(CACHE_NAME).then((cache) => {
                            cache.put(request, response);
                        });
                    }
                });
                return cached;
            }

            return fetch(request).then((response) => {
                // Cache new static assets
                if (response.ok && (
                    request.url.endsWith('.js') ||
                    request.url.endsWith('.css') ||
                    request.url.endsWith('.html')
                )) {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(request, clone);
                    });
                }
                return response;
            });
        })
    );
});

// Background sync for offline actions
self.addEventListener('sync', (event) => {
    if (event.tag === 'sync-scan-result') {
        event.waitUntil(syncScanResults());
    }
});

async function syncScanResults() {
    // Sync any pending data when back online
    console.log('🔄 Syncing data...');
}
