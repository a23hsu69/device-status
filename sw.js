const CACHE = 'dsc-v42';
const STATIC = ['./index.html', './manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(STATIC)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.hostname === 'devicehealth.ldb.co.in') {
    e.respondWith(fetch(e.request).catch(() => new Response('', { status: 503 })));
    return;
  }
  if (e.request.mode === 'navigate' || url.pathname.endsWith('.html') || url.pathname.endsWith('.json')) {
    e.respondWith(
      fetch(e.request)
        .then(response => {
          if (response && response.status === 200) {
            caches.open(CACHE).then(c => c.put(e.request, response.clone()));
          }
          return response;
        })
        .catch(() => caches.match(e.request).then(cached => cached || caches.match('./index.html')))
    );
    return;
  }
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request))
  );
});

// ── Push notification handler ──────────────────────────────────
self.addEventListener('push', e => {
  e.waitUntil((async () => {
    let title = 'Device Status Alert';
    let body  = 'Tap to open the app';
    let tag   = 'device-alert';
    let url   = self.registration.scope;

    // Parse payload — be very defensive, e.data can be null on some Androids
    if (e.data) {
      try {
        const raw = e.data.text();
        if (raw && raw.trim().startsWith('{')) {
          const parsed = JSON.parse(raw);
          title = parsed.title || title;
          body  = parsed.body  || body;
          tag   = parsed.tag   || tag;
          url   = parsed.url   || url;
        } else if (raw && raw.trim()) {
          body = raw.trim();
        }
      } catch (err) {
        // Parsing failed — use defaults, still show notification
        console.warn('[SW] Push data parse failed:', err.message);
      }
    }

    // Always show — never skip even if data is empty
    await self.registration.showNotification(title, {
      body,
      icon:              './icons/icon-192.png',
      badge:             './icons/favicon-32.png',
      tag,
      renotify:          true,
      requireInteraction: false,   // false = auto-dismiss after a few seconds on Android
      vibrate:           [200, 100, 200],
      data:              { url, title, body },
      actions: [
        { action: 'open',    title: 'Open app' },
        { action: 'dismiss', title: 'Dismiss'  }
      ]
    });

    // Also notify any open app windows to show the in-app alert bar
    const clients = await self.clients.matchAll({ type: 'window' });
    clients.forEach(client => client.postMessage({ type: 'PUSH_RECEIVED', title, body }));
  })());
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  if (e.action === 'dismiss') return;
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      for (const client of clientList) {
        if (client.url && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(e.notification.data.url || '/');
    })
  );
});
