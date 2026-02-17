// script/sw.js - SafeVault Service Worker (minimal & safe)
const STATIC_CACHE = 'safevault-static-v1';
const DYNAMIC_CACHE = 'safevault-dynamic-v1';

// Resolve scope path (guaranteed to end with '/'), fallback to '/'
const SCOPE_PATH = (() => {
  try {
    const p = new URL(self.registration.scope).pathname;
    return p.endsWith('/') ? p : p + '/';
  } catch (e) {
    return '/';
  }
})();

// Core assets relative to scope
const ICON_FILES = [
  `${SCOPE_PATH}img/apple-icon-57x57.png`,
  `${SCOPE_PATH}img/apple-icon-60x60.png`,
  `${SCOPE_PATH}img/apple-icon-72x72.png`,
  `${SCOPE_PATH}img/apple-icon-76x76.png`,
  `${SCOPE_PATH}img/apple-icon-114x114.png`,
  `${SCOPE_PATH}img/apple-icon-120x120.png`,
  `${SCOPE_PATH}img/apple-icon-144x144.png`,
  `${SCOPE_PATH}img/apple-icon-152x152.png`,
  `${SCOPE_PATH}img/apple-icon-180x180.png`,
  `${SCOPE_PATH}img/android-icon-192x192.png`,
  `${SCOPE_PATH}img/favicon-32x32.png`,
  `${SCOPE_PATH}img/favicon-16x16.png`,
  `${SCOPE_PATH}img/favicon-96x96.png`,
  `${SCOPE_PATH}img/ms-icon-144x144.png`,
  `${SCOPE_PATH}img/logo.png`
];

const APP_SHELL = [
  `${SCOPE_PATH}`, // start_url
  `${SCOPE_PATH}index.html`,
  `${SCOPE_PATH}css/style.css`,
  `${SCOPE_PATH}css/sv-recovery.css`,
  `${SCOPE_PATH}script/script.js`,
  `${SCOPE_PATH}doc/manifest.json`,
  ...ICON_FILES
];

// Optional CDN list (we won't block install on these)
const CDN_RESOURCES = [
  'https://unpkg.com/@phosphor-icons/web',
  'https://cdnjs.cloudflare.com/ajax/libs/argon2-browser/1.18.0/argon2-bundled.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js'
];

// Install - cache core app shell (do not fail install because of a missing optional asset)
self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(STATIC_CACHE).then(cache =>
      cache.addAll(APP_SHELL).catch(err => {
        // don't fail install for single missing file, but log
        console.warn('[SW] Some APP_SHELL items failed to cache:', err);
      })
    )
  );
});

// Activate - cleanup old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(k => {
          if (![STATIC_CACHE, DYNAMIC_CACHE].includes(k)) {
            return caches.delete(k);
          }
        })
      )
    ).then(() => self.clients.claim())
  );
});

// Fetch - decide strategy by request type
self.addEventListener('fetch', (event) => {
  const req = event.request;
  
  // Only handle GET
  if (req.method !== 'GET') return;
  
  const url = new URL(req.url);
  
  // Ignore browser-sync / dev tools patterns
  if (url.pathname.includes('browser-sync') || url.hostname.includes('localhost')) return;
  
  // Images & icons -> Cache First
  if (url.pathname.match(/\.(png|jpg|jpeg|gif|svg|ico|webp)$/)) {
    event.respondWith(handleImageRequest(event));
    return;
  }
  
  // CSS / JS / fonts / JSON -> Cache First
  if (url.pathname.match(/\.(css|js|json|woff2?|ttf|eot)$/)) {
    event.respondWith(handleStaticAsset(event));
    return;
  }
  
  // Navigation (HTML) -> Network First, fallback to cache
  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    event.respondWith(handleNavigation(event));
    return;
  }
  
  // CDN domains -> Try cache then network
  if (url.hostname.includes('cdnjs') || url.hostname.includes('unpkg')) {
    event.respondWith(handleCdn(event));
    return;
  }
  
  // Default -> Network First with cache fallback
  event.respondWith(handleDefault(event));
});

// Cache-first for images/icons, with background update
async function handleImageRequest(event) {
  const req = event.request;
  const cache = await caches.open(STATIC_CACHE);
  const cached = await cache.match(req);
  if (cached) {
    // background update (non-blocking)
    event.waitUntil(updateCache(req, STATIC_CACHE));
    return cached;
  }
  
  try {
    const res = await fetch(req);
    if (res && res.ok) {
      cache.put(req, res.clone()).catch(() => {});
    }
    return res;
  } catch (err) {
    // fallback to logo if available, else 503
    const fallback = await caches.match(`${SCOPE_PATH}img/logo.png`);
    return fallback || new Response('Image unavailable', { status: 503 });
  }
}

// Cache-first for static assets
async function handleStaticAsset(event) {
  const req = event.request;
  const cache = await caches.open(STATIC_CACHE);
  const cached = await cache.match(req);
  if (cached) return cached;
  
  try {
    const res = await fetch(req);
    if (res && res.ok) {
      cache.put(req, res.clone()).catch(() => {});
    }
    return res;
  } catch (err) {
    return new Response('Resource unavailable', { status: 503 });
  }
}

// Navigation: network-first, then cache (cache index.html fallback)
async function handleNavigation(event) {
  const req = event.request;
  try {
    const res = await fetch(req);
    if (res && res.ok) {
      const dynamic = await caches.open(DYNAMIC_CACHE);
      dynamic.put(req, res.clone()).catch(() => {});
      // also update cached index.html for fallback convenience
      const staticCache = await caches.open(STATIC_CACHE);
      staticCache.put(`${SCOPE_PATH}index.html`, res.clone()).catch(() => {});
      return res;
    }
  } catch (err) {
    // offline fallback
    const cached = await caches.match(req);
    if (cached) return cached;
    const index = await caches.match(`${SCOPE_PATH}index.html`);
    if (index) return index;
  }
  
  return new Response('Offline - SafeVault unavailable', { status: 503, headers: { 'Content-Type': 'text/plain' } });
}

// CDN: try cache else network; do not store huge responses
async function handleCdn(event) {
  const req = event.request;
  const cached = await caches.match(req);
  if (cached) return cached;
  
  try {
    const res = await fetch(req);
    if (res && res.ok) {
      const dyn = await caches.open(DYNAMIC_CACHE);
      dyn.put(req, res.clone()).catch(() => {});
    }
    return res;
  } catch (err) {
    return new Response('CDN resource unavailable', { status: 503 });
  }
}

// Default: network-first with cache fallback
async function handleDefault(event) {
  const req = event.request;
  try {
    const res = await fetch(req);
    if (res && res.ok) {
      const dyn = await caches.open(DYNAMIC_CACHE);
      dyn.put(req, res.clone()).catch(() => {});
    }
    return res;
  } catch (err) {
    const cached = await caches.match(req);
    if (cached) return cached;
    return new Response('Resource unavailable offline', { status: 503 });
  }
}

// Update cache helper (background)
async function updateCache(request, cacheName = DYNAMIC_CACHE) {
  try {
    const res = await fetch(request);
    if (res && res.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, res.clone()).catch(() => {});
    }
  } catch (e) {
    // silent
  }
}

// Simple messaging API: clear caches or prefetch icons
self.addEventListener('message', (event) => {
  const data = event.data;
  if (!data) return;
  
  if (data === 'skipWaiting') return self.skipWaiting();
  
  if (data.type === 'CLEAR_CACHE') {
    event.waitUntil(Promise.all([caches.delete(DYNAMIC_CACHE), caches.delete(STATIC_CACHE)]));
  }
  
  if (data.type === 'PREFETCH_ICONS') {
    event.waitUntil(caches.open(STATIC_CACHE).then(c => c.addAll(ICON_FILES).catch(() => {})));
  }
});
