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

const SW_VERSION = 6;
const CACHE = `halyard-shell-v${SW_VERSION}`;

// Token-free URLs only. /manifest.json bakes the token into start_url and is
// therefore served 401 without one - it must never go back in this list.
const SHELL_URLS = ['/icon.svg'];
// Holds one "Share -> Halyard" hand-off between this worker and the page it
// redirects to. Never touched by the activate cleanup below, or a worker update
// in between would eat a share in flight.
const SHARE_CACHE = 'halyard-share';
// The last page shell the network returned, kept so the app still opens with
// no signal and can park a message in its outbox. Filled at RUNTIME from a
// real navigation, never precached: the shell is behind the token, and a
// precache entry that 401s is how an install used to fail (see the top of this
// file). The key carries no token; the cached HTML contains none either.
const PAGE_CACHE = 'halyard-page';
const PAGE_KEY = '/__shell';

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
    await Promise.all(names.filter((n) => n !== CACHE && n !== SHARE_CACHE && n !== PAGE_CACHE).map((n) => caches.delete(n)));
    await self.clients.claim();
  })());
});

// --- Share target ----------------------------------------------------------
// The manifest's share_target posts what another app shared (title/text/url and
// at most one file) to /share. A page cannot read a POST body after a redirect,
// so the worker parks it in SHARE_CACHE and sends the page ?shared=1 to pick it
// up into the compose box - nothing is queued until the phone presses Send.
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.pathname === '/share' && event.request.method === 'POST') {
    event.respondWith(receiveShare(event.request, url));
    return;
  }
  if (event.request.mode === 'navigate' && (url.pathname === '/' || url.pathname === '/index.html')) {
    event.respondWith(pageNetworkFirst(event.request));
  }
  // Anything else is not intercepted at all - true network passthrough.
});

async function pageNetworkFirst(request) {
  const cache = await caches.open(PAGE_CACHE);
  try {
    // Four seconds: a tunnel that is down often hangs rather than fails, and
    // waiting out the browser's own timeout is a minute of white screen.
    const res = await Promise.race([
      fetch(request),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 4000)),
    ]);
    // Only a good shell is kept. A 401 page must never replace it.
    if (res.ok) cache.put(PAGE_KEY, res.clone()).catch(() => {});
    return res;
  } catch (e) {
    const hit = await cache.match(PAGE_KEY);
    if (hit) return hit;
    throw e;
  }
}

async function receiveShare(request, url) {
  const back = (st) => Response.redirect(`/?token=${encodeURIComponent(url.searchParams.get('token') || '')}&shared=${st}`, 303);
  try {
    const form = await request.formData();
    const cache = await caches.open(SHARE_CACHE);
    const str = (k) => { const v = form.get(k); return typeof v === 'string' ? v : ''; };
    const meta = { title: str('title'), text: str('text'), url: str('url'), at: Date.now() };
    const file = form.get('file');
    if (file && typeof file !== 'string' && file.size > 0) {
      meta.fileName = file.name || 'shared';
      meta.fileType = file.type || '';
      await cache.put('/__share/file', new Response(file));
    } else {
      await cache.delete('/__share/file');
    }
    await cache.put('/__share/meta', new Response(JSON.stringify(meta), { headers: { 'Content-Type': 'application/json' } }));
    return back('1');
  } catch (e) {
    return back('failed');
  }
}

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
  //
  // Built from the REAL options the caller gave `/api/ask`, never a hardcoded
  // Approve/Deny. A free-text question passes an empty options array on purpose
  // (see `halyard ask`), which is what falls through to the text box below
  // rather than showing buttons that do not apply to it.
  //
  // ONE button, never two. On a POCO phone (HyperOS, Chrome) every action button
  // delivered the LAST action's id: tapping Approve sent "Deny", and tapping the
  // left of two test options sent the right one (reproduced three times on the
  // phone bridge Halyard grew from). A single button has nothing to collide with.
  // The other options - Deny included - are in the page a body tap opens, and an
  // approval left unanswered still denies on the relay's timeout. Don't go back
  // to two buttons without re-testing on a real Android phone.
  const askOptions = Array.isArray(payload.actions) ? payload.actions.filter(Boolean).slice(0, 1) : [];
  // `review` means the command was too long for the notification body. Offering
  // Approve there would be approving text that was cut off, so the notification
  // carries no actions at all and a tap opens the page, where the whole command
  // is on screen.
  const actions = payload.review
    ? []
    : (payload.kind === 'ask' && askOptions.length
      ? askOptions.map((label, i) => ({ action: `opt${i}`, title: String(label) }))
      : [{ action: 'reply', title: 'Reply', type: 'text', placeholder: 'Reply…' }]);

  event.waitUntil(self.registration.showNotification(payload.title || 'Halyard', {
    body: payload.body || '',
    icon: '/icon.svg',
    badge: '/icon.svg',
    tag: payload.kind === 'ask' ? `halyard-ask-${payload.id || Date.now()}` : `halyard-${payload.id || Date.now()}`,
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

    const optMatch = /^opt(\d)$/.exec(action || '');
    if (optMatch) {
      const label = Array.isArray(data.actions) ? data.actions[Number(optMatch[1])] : null;
      try {
        const res = await fetch(`/api/answer${q}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id: data.id, answer: label || action }),
        });
        if (res.status === 409) return report('That question is no longer current.');
        return report(res.ok ? `Sent: ${label || action}` : `Failed (${res.status}).`);
      } catch (e) {
        return report('Could not reach Halyard.');
      }
    }

    // A free-text reply answers two different things depending on kind, and
    // sending it to the wrong one is worse than not sending it at all: for an
    // `ask` it must land on /api/answer (the one pending question this device
    // is looking at), never /api/inbox (which would start an unrelated new
    // conversation turn wearing the same clothes as an answer).
    if (action === 'reply' && event.reply && data.kind === 'ask') {
      try {
        const res = await fetch(`/api/answer${q}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id: data.id, answer: event.reply }),
        });
        if (res.status === 409) return report('That question is no longer current.');
        return report(res.ok ? 'Sent.' : `Failed (${res.status}).`);
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
