// Service worker: push delivery, and answering an approve/deny straight from
// the notification.
//
// THE MOST IMPORTANT RULE IN THIS FILE
//
// An install that rejects never activates, and the previously-installed worker
// keeps control indefinitely. That failure is close to undiagnosable from the
// server side: the push service returns 201, the log looks perfect, the tests
// pass (they test the file on disk, not what is running on the phone) - and the
// phone shows nothing, forever.
//
// It happened because precaching used `cache.addAll([...])`, one entry of which
// was token-gated. A service worker's own fetches carry no token, so that entry
// 401'd, addAll rejected on the non-2xx, and the rejection propagated through
// event.waitUntil().
//
// Hence, three rules, all pinned by test/smoke.js:
//   1. Everything in SHELL_URLS must be fetchable WITHOUT a token.
//   2. Precaching must not be able to fail the install - each asset is added
//      individually with its own catch.
//   3. SW_VERSION and the page's REQUIRED_SW_VERSION are bumped together.

const SW_VERSION = 1;
const CACHE = `halyard-shell-v${SW_VERSION}`;

// Token-free URLs only. /manifest.json bakes the token into start_url and is
// therefore served 401 without one - it must never go back in this list.
const SHELL_URLS = ['/icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await Promise.all(SHELL_URLS.map((u) => cache.add(u).catch(() => {})));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n)));
    await self.clients.claim();
  })());
});

// The page asks for this to detect a stale worker. An old worker has no handler
// here and simply does not reply, which is why the page treats silence as
// inconclusive rather than as "no worker".
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'version' && event.ports[0]) {
    event.ports[0].postMessage({ version: SW_VERSION });
  }
});

self.addEventListener('push', (event) => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; } catch (e) { payload = { body: event.data ? event.data.text() : '' }; }

  // Store the WHOLE payload. An earlier version built `data: { url: '/' }` by
  // hand and threw the payload away - so the tokened URL the server has always
  // sent for exactly this purpose never reached notificationclick, and every
  // tap with no tab open landed on the 401 page.
  const actions = payload.kind === 'ask'
    ? [{ action: 'approve', title: 'Approve' }, { action: 'deny', title: 'Deny' }]
    : [{ action: 'reply', title: 'Reply', type: 'text', placeholder: 'Reply…' }];

  event.waitUntil(self.registration.showNotification(payload.title || 'Halyard', {
    body: payload.body || '',
    icon: '/icon.svg',
    badge: '/icon.svg',
    tag: payload.kind === 'ask' ? 'halyard-ask' : `halyard-${payload.id || Date.now()}`,
    data: payload,
    // Platforms that support no actions (iOS) ignore this list and still show a
    // tappable notification - exactly the behaviour before actions existed.
    actions,
  }));
});

// The worker stores no credentials. It reads the token out of the payload's own
// url, and the payload is encrypted to the subscribing browser (RFC 8291),
// which by definition already holds that token.
function tokenFrom(data) {
  try { return new URL(data.url, self.location.origin).searchParams.get('token') || ''; } catch (e) { return ''; }
}

async function report(text) {
  // Every action reports its outcome. There is no page watching for an error,
  // and a tap that silently did nothing is indistinguishable from one that
  // worked - which, on an Approve, is the difference between a command running
  // and the relay timing out.
  await self.registration.showNotification('Halyard', { body: text, icon: '/icon.svg', tag: 'halyard-result' });
}

self.addEventListener('notificationclick', (event) => {
  const data = event.notification.data || {};
  const token = tokenFrom(data);
  const action = event.action;
  event.notification.close();

  event.waitUntil((async () => {
    const q = `?token=${encodeURIComponent(token)}`;

    if (action === 'approve' || action === 'deny') {
      try {
        const res = await fetch(`/api/answer${q}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id: data.id, answer: action === 'approve' ? 'Approve' : 'Deny' }),
        });
        if (res.status === 409) return report('That question is no longer current.');
        return report(res.ok ? `Sent: ${action}` : `Failed (${res.status}).`);
      } catch (e) {
        return report('Could not reach Halyard.');
      }
    }

    if (action === 'reply' && event.reply) {
      try {
        const res = await fetch(`/api/inbox${q}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          // Carries the thread and engine of the reply it answers, or it would
          // quietly start a different conversation on the default thread
          // wearing the same clothes.
          body: JSON.stringify({ message: event.reply, thread: data.thread || 'main', engine: data.engine || '' }),
        });
        return report(res.ok ? 'Queued.' : `Failed (${res.status}).`);
      } catch (e) {
        return report('Could not reach Halyard.');
      }
    }

    // A plain tap: focus an open tab if there is one, otherwise open the
    // tokened URL from the payload.
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of clients) {
      if (c.url.includes(self.location.origin)) return c.focus();
    }
    return self.clients.openWindow(data.url || '/');
  })());
});
