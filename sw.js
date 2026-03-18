const CACHE = 'dsc-v40';
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
  console.log('[SW] Push received, data type:', e.data ? typeof e.data : 'none');

  e.waitUntil((async () => {
    let title = 'Device Status Alert';
    let body = 'A device needs attention';
    let tag = 'device-alert';
    let url = self.registration.scope;

    if (e.data) {
      const raw = e.data.text();
      console.log('[SW] Raw push data:', raw.substring(0, 200));
      try {
        const parsed = JSON.parse(raw);
        title = parsed.title || title;
        body = parsed.body || body;
        tag = parsed.tag || tag;
        url = parsed.url || url;
        console.log('[SW] Parsed title:', title, 'body:', body);
      } catch(err) {
        console.log('[SW] Not JSON, using raw as body:', raw);
        body = raw || body;
      }
    }

    const options = {
      body: body,
      icon: './icons/icon-192.png',
      badge: './icons/favicon-32.png',
      tag: tag,
      renotify: true,
      requireInteraction: true,
      vibrate: [200, 100, 200],
      data: { url: url, title: title, body: body },
      actions: [
        { action: 'open', title: 'Open app' },
        { action: 'dismiss', title: 'Dismiss' }
      ]
    };

    await self.registration.showNotification(title, options);
    console.log('[SW] Notification shown:', title);

    // Notify all open clients to show in-app alert bar
    const clients = await self.clients.matchAll({ type: 'window' });
    clients.forEach(client => client.postMessage({
      type: 'PUSH_RECEIVED',
      title: title,
      body: body
    }));
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
