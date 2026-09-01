// The HTTP server: the phone's only point of contact with this machine.
//
// Zero dependencies, node:http only. That is not asceticism - it is what makes
// "clone it and run it" true on a machine you do not control, and it means the
// supply chain for a service holding a bearer token and an agent's leash is
// node itself.
//
// The shape of the thing: a message queue in one direction, a reply ring in the
// other, a change-notification stream so the phone does not have to poll, and a
// small pile of routes for the things that turned out to matter once it was in
// daily use (retry, transcripts, artifacts, spend, logs).

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const threads = require('./threads');
const push = require('./push');
const lockmod = require('./lock');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// ---------------------------------------------------------------------------
// Small helpers

function json(res, status, body, extraHeaders) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
    // The page is same-origin and loads no third-party anything, so the
    // strictest useful policy costs nothing here.
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  res.end(payload);
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) {
        // 413 rather than a silent truncation: a half-read upload that looks
        // like a success is worse than a clear refusal.
        const err = new Error('payload too large');
        err.status = 413;
        req.destroy();
        return reject(err);
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJson(req, maxBytes = 1024 * 1024) {
  const buf = await readBody(req, maxBytes);
  if (!buf.length) return {};
  try {
    const parsed = JSON.parse(buf.toString('utf8'));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (e) {
    const err = new Error('invalid JSON body');
    err.status = 400;
    throw err;
  }
}

function newId() {
  return crypto.randomBytes(9).toString('base64url');
}

// Constant-time compare so the token cannot be recovered a byte at a time by
// timing the 401s. Lengths are compared first because timingSafeEqual throws on
// a mismatch, and that throw is itself a length oracle - hence the hash.
function tokenMatches(a, b) {
  const ha = crypto.createHash('sha256').update(String(a || '')).digest();
  const hb = crypto.createHash('sha256').update(String(b || '')).digest();
  return crypto.timingSafeEqual(ha, hb) && String(a).length > 0;
}

function clampInt(v, min, max, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

function clampStr(v, max) {
  if (typeof v !== 'string') return '';
  return v.slice(0, max);
}

// ---------------------------------------------------------------------------
// Repeats and deferrals

const REPEATS = new Set(['daily', 'weekdays', 'weekly']);
const MAX_DEFER_MS = 30 * 24 * 3600 * 1000;

// Steps with setDate, NEVER by adding 24h of milliseconds. A repeat pinned to
// 07:00 has to stay at 07:00 across a daylight-saving change instead of
// drifting by an hour for half the year.
//
// It also skips forward past ALL missed slots rather than firing once per
// skipped day, so a machine asleep for a week catches up to the next future
// slot on wake instead of delivering seven backdated runs.
function nextOccurrence(from, repeat, now = Date.now()) {
  if (!REPEATS.has(repeat)) return null;
  const d = new Date(from);
  let guard = 0;
  do {
    if (repeat === 'weekly') d.setDate(d.getDate() + 7);
    else d.setDate(d.getDate() + 1);
    if (repeat === 'weekdays') {
      while (d.getDay() === 0 || d.getDay() === 6) d.setDate(d.getDate() + 1);
    }
  } while (d.getTime() <= now && guard++ < 4000);
  return d.getTime();
}

function isDue(item, now = Date.now()) {
  return !item.runAfter || item.runAfter <= now;
}

// ---------------------------------------------------------------------------
// Append-only archives (replies, run ledger)
//
// Flat JSONL, compacted by size. The archive is the ONLY durable copy of a
// reply: the notification ring caps at 30, the phone's local history is
// per-device and only holds what arrived while that device had the page open.

function appendJsonl(file, obj, maxBytes) {
  try {
    fs.appendFileSync(file, `${JSON.stringify(obj)}\n`);
    const st = fs.statSync(file);
    if (st.size > maxBytes) {
      const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
      fs.writeFileSync(file, `${lines.slice(Math.floor(lines.length / 2)).join('\n')}\n`);
    }
  } catch (e) {
    // An archive write failing must not fail the reply it was archiving.
  }
}

function readJsonl(file, limit = Infinity) {
  try {
    const out = [];
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      if (!line) continue;
      try { out.push(JSON.parse(line)); } catch (e) { /* skip a torn line */ }
      if (out.length > limit * 4) out.shift();
    }
    return out;
  } catch (e) {
    return [];
  }
}

// ---------------------------------------------------------------------------
// The server

function createServer(ctx) {
  const { cfg, paths, log, token } = ctx;

  // --- state -------------------------------------------------------------
  //
  // Persisted: the queue and the reply ring. Both survive a restart because a
  // restart mid-conversation is routine (the agent is allowed to edit this
  // server and restart it), and before persistence each one silently discarded
  // every queued message and the whole reply history, with the phone simply
  // never hearing back and nothing anywhere explaining why.
  //
  // NOT persisted: `current` (the in-flight approve/deny question) and
  // `activeRun`. A question outliving the run that asked it is worse than no
  // question - the relay hook denies on timeout, which is the safe default -
  // and after a restart the phone should show no run rather than a run it can
  // no longer cancel.
  const state = {
    inbox: [],
    notifications: [],
    lastFailed: null,
    current: null,
    activeRun: null,
    transcripts: {},
  };

  function loadState() {
    try {
      const raw = JSON.parse(fs.readFileSync(paths.state, 'utf8'));
      if (Array.isArray(raw.inbox)) state.inbox = raw.inbox;
      if (Array.isArray(raw.notifications)) state.notifications = raw.notifications;
      if (raw.lastFailed) state.lastFailed = raw.lastFailed;
      log.info(`restored ${state.inbox.length} queued, ${state.notifications.length} replies`);
    } catch (e) {
      // A corrupt state file is logged and skipped, never fatal. An unreachable
      // bridge is worse than a lost queue.
      if (e.code !== 'ENOENT') log.warn(`state.json unreadable (${e.message}); starting empty`);
    }
  }

  // The single choke point for everything persisted, which is what makes it
  // the one place that cannot miss a change-stream bump. Deliberately coarse -
  // it wakes `health` and `notifications` together - because an over-broad wake
  // costs one extra fetch and a missed one costs stale data until a fallback
  // tick.
  function saveState() {
    try {
      fs.writeFileSync(paths.state, JSON.stringify({
        inbox: state.inbox,
        notifications: state.notifications,
        lastFailed: state.lastFailed,
      }));
    } catch (e) {
      log.error(`could not persist state: ${e.message}`);
    }
    bump('state', 'health', 'notifications');
  }

  // --- change stream -----------------------------------------------------
  //
  // GET /api/events publishes ONLY a version counter per channel. It is a
  // change-notification channel, not a data channel: the page reacts by calling
  // the same poll function it already had, so every render path, payload shape
  // and auth check stays exactly as it was and as it was already tested. The
  // stream only replaces the question "has anything changed yet?", which is the
  // part a timer answers badly - 90% of the request log for no freshness.
  const versions = { state: 0, notifications: 0, health: 0, context: 0, artifacts: 0 };
  const sseClients = new Set();

  function bump(...channels) {
    for (const c of channels) versions[c] = (versions[c] || 0) + 1;
    const payload = `data: ${JSON.stringify(versions)}\n\n`;
    for (const res of sseClients) {
      try { res.write(payload); } catch (e) { sseClients.delete(res); }
    }
  }

  // handover files, session files and artifacts are written by the agent and
  // the watcher, never through a route, so nothing here knows they changed
  // unless it looks. Watch the DIRECTORY, not the files: a handover file is
  // deleted and recreated by "clear context", and a file watch does not survive
  // that - it would go quiet exactly when the content mattered most.
  const watchers = [];
  function watchDir(dir, channel) {
    let timer = null;
    let real = dir;
    try { real = fs.realpathSync.native(dir); } catch (e) { /* ignore - keep raw path */ }
    try {
      const w = fs.watch(real, { persistent: false }, () => {
        clearTimeout(timer);
        // Directory watching means seeing every write in the folder, hence the
        // debounce: a run writing a dozen files should wake the phone once.
        timer = setTimeout(() => bump(channel), 150);
      });
      watchers.push({ w, stop: () => clearTimeout(timer) });
    } catch (e) {
      log.debug(`cannot watch ${dir}${real && real !== dir ? ` (${real})` : ''}: ${e.message}`);
    }
  }

  // --- delivery ----------------------------------------------------------

  async function deliver(entry) {
    const url = `${cfg.publicUrl || ''}/?token=${encodeURIComponent(token)}`;
    // The payload carries a tokened URL because a notification tap with no tab
    // open has to open one, and a bare "/" lands on the 401 page. Not a new
    // disclosure: the payload is encrypted to the browser that subscribed,
    // which by definition already holds that token.
    const body = {
      title: entry.internal ? 'Halyard' : `Reply · ${entry.thread || 'main'}`,
      body: clampStr(entry.message, 400),
      url,
      id: entry.id,
      thread: entry.thread || 'main',
      engine: entry.engine || '',
      kind: entry.kind || 'reply',
    };

    if (cfg.push && cfg.push.enabled) {
      const keys = ctx.pushKeys();
      const subs = ctx.pushSubs();
      if (keys && subs.length) {
        for (const sub of subs) {
          const r = await push.sendNotification(sub, JSON.stringify(body), keys, cfg.push.subject);
          // Pruned ONLY on 404/410 - the service saying this endpoint is
          // permanently dead. A transient 5xx, or a phone that is merely
          // offline, must never silently unsubscribe anyone.
          if (r.gone) ctx.removePushSub(sub.endpoint);
          else if (!r.ok) log.warn(`push to ${new URL(sub.endpoint).host} failed: ${r.status} ${r.error || ''}`);
        }
      }
    }

    if (cfg.ntfy && cfg.ntfy.enabled && cfg.ntfy.topic) {
      try {
        await fetch(`https://ntfy.sh/${encodeURIComponent(cfg.ntfy.topic)}`, {
          method: 'POST',
          body: clampStr(entry.message, 2000),
          headers: { Title: body.title },
          signal: AbortSignal.timeout(10000),
        });
      } catch (e) {
        log.warn(`ntfy delivery failed: ${e.message}`);
      }
    }
  }

  function addNotification(entry) {
    state.notifications.unshift(entry);
    state.notifications.length = Math.min(state.notifications.length, cfg.notificationRing);
    appendJsonl(paths.replies, entry, cfg.archiveMaxBytes);
    // The ledger excludes internal notices - it is a cost rollup and they would
    // skew every average - but the ARCHIVE keeps them, because "when did the
    // watcher last fail" is a question the archive should be able to answer.
    if (!entry.internal && Number.isFinite(entry.costUsd)) {
      appendJsonl(paths.runs, {
        at: entry.at, thread: entry.thread, engine: entry.engine,
        model: entry.model, costUsd: entry.costUsd, durationMs: entry.durationMs,
        numTurns: entry.numTurns,
      }, cfg.archiveMaxBytes);
    }
    saveState();
    deliver(entry).catch((e) => log.warn(`delivery failed: ${e.message}`));
  }

  function notifyInternal(message) {
    addNotification({
      id: newId(), at: Date.now(), message: `[halyard] ${message}`,
      thread: 'main', internal: true, kind: 'internal',
    });
  }

  // --- transcripts -------------------------------------------------------
  //
  // The activity line kept instead of overwritten, so a twenty-minute run can
  // be read as it happens. Deliberately NOT on /api/health: health is refetched
  // on every activity bump, and echoing a 200-entry array back on each one is
  // tens of KB per tool call over a phone's connection. Health carries the
  // counter; the page fetches the delta it is missing.
  function transcriptFor(engine) {
    if (!state.transcripts[engine]) state.transcripts[engine] = { runId: '', seq: 0, lines: [], draft: '' };
    return state.transcripts[engine];
  }

  // --- artifacts ---------------------------------------------------------
  //
  // One resolver for GET and DELETE both, so the containment check cannot be
  // present on one and missing on the other.
  function resolveArtifact(pathname) {
    const rel = decodeURIComponent(pathname.replace(/^\/artifacts\/?/, ''));
    const full = path.resolve(paths.artifacts, rel);
    const root = path.resolve(paths.artifacts);
    // Prefix-with-separator, not startsWith on the bare root: `/artifacts-evil`
    // starts with `/artifacts`.
    if (full !== root && !full.startsWith(root + path.sep)) return null;
    return full;
  }

  // The log tail is an ALLOW-LIST, never a path.
  //
  // This route reads arbitrary bytes back to the caller, and the token file and
  // the push keypair sit in the same directory. So the query names a KEY into a
  // map of absolute paths - `?file=halyard.log`, `?file=../token.txt` and
  // `?file=/etc/passwd` are all 400s.
  const LOG_FILES = {
    halyard: paths.log,
    messages: paths.messages,
    replies: paths.replies,
    runs: paths.runs,
  };

  // ---------------------------------------------------------------------
  // Routes

  const routes = {};
  const route = (method, p, fn) => { routes[`${method} ${p}`] = fn; };

  // --- queue -------------------------------------------------------------

  route('POST', '/api/inbox', async (req, res, url) => {
    const body = await readJson(req);
    const message = clampStr(body.message, 100000).trim();
    if (!message) return json(res, 400, { error: 'message is required' });

    const item = {
      id: newId(),
      at: Date.now(),
      message,
      thread: threads.normalize(body.thread),
      engine: cfg.engines[body.engine] ? body.engine : cfg.defaultEngine,
      model: clampStr(body.model, 64),
      // Clamped server-side. A phone with a wrong clock, or a typo, should not
      // be able to park a message past the heat death of the universe.
      runAfter: Number.isFinite(Number(body.runAfter))
        ? clampInt(body.runAfter, Date.now(), Date.now() + MAX_DEFER_MS, 0) || null
        : null,
      repeat: REPEATS.has(body.repeat) ? body.repeat : null,
    };
    if (body.front) state.inbox.unshift(item); else state.inbox.push(item);
    saveState();
    log.info(`queued ${item.id}`, { thread: item.thread, engine: item.engine });
    ctx.nudge();
    return json(res, 200, { ok: true, id: item.id, queued: state.inbox.length });
  });

  route('GET', '/api/inbox', async (req, res) => json(res, 200, { items: state.inbox, lastFailed: state.lastFailed }));

  // pop and peek return the first DUE item rather than the first item, so a
  // deferred message never blocks the ones behind it.
  route('POST', '/api/inbox/peek', async (req, res) => {
    const item = state.inbox.find((i) => isDue(i)) || null;
    return json(res, 200, { item });
  });

  route('POST', '/api/inbox/pop', async (req, res) => {
    const idx = state.inbox.findIndex((i) => isDue(i));
    if (idx === -1) return json(res, 200, { item: null });
    const [item] = state.inbox.splice(idx, 1);

    // A repeat leaves a SUCCESSOR behind on pop, not after a successful run. A
    // repeat that only survived a good run would silently stop the first time a
    // run failed, which is the opposite of what a standing job should do. Doing
    // it here also means there is only ever one instance of a repeat in the
    // queue at a time, so every existing path (isDue, peek, health, retry)
    // works unchanged.
    if (item.repeat) {
      const next = nextOccurrence(item.runAfter || item.at, item.repeat);
      if (next) state.inbox.push({ ...item, id: newId(), at: Date.now(), runAfter: next });
    }
    saveState();
    return json(res, 200, { item });
  });

  route('POST', '/api/inbox/retry', async (req, res) => {
    if (!state.lastFailed) return json(res, 404, { error: 'nothing to retry' });
    // Rebuilt WITHOUT `repeat`: retrying a repeat runs it once and does not
    // create a second recurring entry - the successor already exists.
    const { message, thread, engine, model } = state.lastFailed;
    // Re-queued at the FRONT. It was first in line before the run ate it.
    state.inbox.unshift({ id: newId(), at: Date.now(), message, thread, engine, model, runAfter: null, repeat: null });
    state.lastFailed = null;
    saveState();
    ctx.nudge();
    return json(res, 200, { ok: true, queued: state.inbox.length });
  });

  route('POST', '/api/inbox/dismiss-failed', async (req, res) => {
    state.lastFailed = null;
    saveState();
    return json(res, 200, { ok: true });
  });

  route('GET', '/api/inbox/scheduled', async (req, res) => {
    const now = Date.now();
    return json(res, 200, { items: state.inbox.filter((i) => !isDue(i, now)) });
  });

  // Scoped to not-yet-due items on purpose, so it cannot race the watcher for a
  // message that is about to be popped.
  route('DELETE', '/api/inbox/scheduled', async (req, res, url) => {
    const id = url.searchParams.get('id');
    const idx = state.inbox.findIndex((i) => i.id === id && !isDue(i));
    if (idx === -1) return json(res, 404, { error: 'no scheduled item with that id' });
    state.inbox.splice(idx, 1);
    saveState();
    return json(res, 200, { ok: true });
  });

  // --- approve / deny relay ----------------------------------------------

  route('POST', '/api/ask', async (req, res) => {
    const body = await readJson(req);
    state.current = {
      id: newId(),
      at: Date.now(),
      question: clampStr(body.question, 500),
      command: clampStr(body.command, 4000),
      options: Array.isArray(body.options) ? body.options.slice(0, 4).map((o) => clampStr(o, 40)) : ['Approve', 'Deny'],
      status: 'pending',
      answer: null,
    };
    // `current` never goes through saveState (it is deliberately not
    // persisted), so the bump is by hand here. Forget it and the phone stops
    // seeing relay questions promptly, which is the thing it most needs to see.
    bump('state', 'health');
    // A relay question is the one notification that is useless if it arrives
    // late: the hook denies on a timeout.
    deliver({
      id: state.current.id, message: `${state.current.question}\n${state.current.command}`,
      thread: 'main', internal: true, kind: 'ask', actions: state.current.options,
    }).catch(() => {});
    return json(res, 200, { id: state.current.id });
  });

  route('GET', '/api/state', async (req, res) => json(res, 200, state.current || { status: 'idle' }));

  route('POST', '/api/answer', async (req, res) => {
    const body = await readJson(req);
    if (!state.current || state.current.status !== 'pending') {
      // 409 rather than 200: "that question is no longer current" is the likely
      // failure for a notification tap, and the worker calls it out by name.
      return json(res, 409, { error: 'no pending question' });
    }
    if (body.id && body.id !== state.current.id) {
      return json(res, 409, { error: 'that question is no longer current' });
    }
    state.current.answer = clampStr(body.answer, 40);
    state.current.status = 'answered';
    bump('state', 'health');
    return json(res, 200, { ok: true });
  });

  // --- replies -----------------------------------------------------------

  route('POST', '/api/notify', async (req, res) => {
    const body = await readJson(req);
    const message = clampStr(body.message, 200000);
    if (!message) return json(res, 400, { error: 'message is required' });
    const entry = {
      id: newId(),
      at: Date.now(),
      message,
      thread: threads.normalize(body.thread),
      engine: clampStr(body.engine, 32),
      prompt: clampStr(body.prompt, 4000),
      model: clampStr(body.model, 64),
      kind: 'reply',
      // Every one of these is optional and clamped. `null` is the "the engine
      // did not report this" signal everywhere in the watcher, and a cost of
      // ZERO is a real result - hence Number.isFinite, never a truthiness test.
      costUsd: Number.isFinite(Number(body.costUsd)) ? Number(body.costUsd) : null,
      durationMs: Number.isFinite(Number(body.durationMs)) ? Number(body.durationMs) : null,
      numTurns: Number.isFinite(Number(body.numTurns)) ? Number(body.numTurns) : null,
    };
    addNotification(entry);
    writeMessageLog(entry);
    return json(res, 200, { ok: true, id: entry.id });
  });

  route('GET', '/api/notifications', async (req, res) => json(res, 200, { items: state.notifications }));

  route('DELETE', '/api/notifications', async (req, res, url) => {
    const id = url.searchParams.get('id');
    if (!id) return json(res, 400, { error: 'id is required' });
    state.notifications = state.notifications.filter((n) => n.id !== id);
    // Deletes from the ARCHIVE unconditionally, not only when the ring held it.
    // "This cannot be undone" is what the phone asks, and the entries most
    // worth deleting are precisely the ones already aged out of the ring.
    try {
      const kept = readJsonl(paths.replies).filter((n) => n.id !== id);
      fs.writeFileSync(paths.replies, kept.map((n) => JSON.stringify(n)).join('\n') + (kept.length ? '\n' : ''));
    } catch (e) {
      log.warn(`archive delete failed: ${e.message}`);
    }
    saveState();
    return json(res, 200, { ok: true });
  });

  // Search the durable archive. Sort BEFORE capping - capping first returns the
  // OLDEST N matches, which is the opposite of what anyone searching wants.
  route('GET', '/api/messages', async (req, res, url) => {
    const rawLimit = url.searchParams.get('limit');
    const limit = rawLimit === null ? 50 : clampInt(rawLimit, 1, 500, 50);
    const q = (url.searchParams.get('q') || '').toLowerCase();
    const thread = url.searchParams.get('thread');
    let items = readJsonl(paths.replies);
    if (q) items = items.filter((n) => String(n.message || '').toLowerCase().includes(q) || String(n.prompt || '').toLowerCase().includes(q));
    if (thread) items = items.filter((n) => n.thread === threads.normalize(thread));
    items.sort((a, b) => b.at - a.at);
    return json(res, 200, { items: items.slice(0, limit), total: items.length });
  });

  // ?days= is presence-checked, not just Number()-ed. searchParams.get returns
  // null for an absent param and Number(null) is 0, which IS finite - so the
  // obvious isFinite guard reads "absent" as "zero" and then clamps it up to
  // the minimum. That shipped once as a documented 7-day default that actually
  // served 1 day, and never surfaced because the page always passed it.
  route('GET', '/api/spend', async (req, res, url) => {
    const rawDays = url.searchParams.get('days');
    const days = rawDays === null ? 7 : clampInt(rawDays, 1, 365, 7);
    const since = Date.now() - days * 24 * 3600 * 1000;
    const rows = readJsonl(paths.runs).filter((r) => r.at >= since);
    const roll = (key) => {
      const m = {};
      for (const r of rows) {
        const k = r[key] || 'unknown';
        if (!m[k]) m[k] = { key: k, runs: 0, costUsd: 0, durationMs: 0 };
        m[k].runs += 1;
        m[k].costUsd += Number(r.costUsd) || 0;
        m[k].durationMs += Number(r.durationMs) || 0;
      }
      return Object.values(m).sort((a, b) => b.costUsd - a.costUsd);
    };
    const byDay = {};
    for (const r of rows) {
      // Local day, not UTC: "what did today cost" is a question about the day
      // the person holding the phone is having.
      const d = new Date(r.at);
      const k = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
      byDay[k] = (byDay[k] || 0) + (Number(r.costUsd) || 0);
    }
    return json(res, 200, {
      days,
      runs: rows.length,
      totalUsd: rows.reduce((a, r) => a + (Number(r.costUsd) || 0), 0),
      byDay: Object.entries(byDay).map(([day, costUsd]) => ({ day, costUsd })).sort((a, b) => a.day.localeCompare(b.day)),
      byThread: roll('thread'),
      byModel: roll('model'),
    });
  });

  // --- run lifecycle -----------------------------------------------------

  route('POST', '/api/run/start', async (req, res) => {
    const b = await readJson(req);
    state.activeRun = {
      runId: clampStr(b.runId, 64) || newId(),
      engine: clampStr(b.engine, 32),
      thread: threads.normalize(b.thread),
      message: clampStr(b.message, 2000),
      model: clampStr(b.model, 64),
      startedAt: Date.now(),
      activity: '',
      killRequested: false,
    };
    const t = transcriptFor(state.activeRun.engine);
    t.runId = state.activeRun.runId;
    t.lines = [];
    t.draft = '';
    // seq keeps climbing ACROSS runs; runId is what signals a reset. Restarting
    // each run's sequence at 0 would hand a phone still holding `since` from the
    // previous run the new run's lines as though it had already seen them.
    t.seq += 1;
    bump('health');
    return json(res, 200, { ok: true, runId: state.activeRun.runId });
  });

  route('POST', '/api/run/activity', async (req, res) => {
    const b = await readJson(req);
    const engine = clampStr(b.engine, 32) || cfg.defaultEngine;
    const t = transcriptFor(engine);
    // Assigned ONLY when the field is present. This used to assign
    // unconditionally, writing null for anything non-string - harmless while
    // every post carried a label, but the moment draft-only posts existed it
    // emptied the activity line mid-run.
    if (typeof b.activity === 'string' && b.activity) {
      if (state.activeRun) state.activeRun.activity = b.activity;
      t.lines.push({ at: Date.now(), seq: t.seq + 1, text: b.activity });
      if (t.lines.length > cfg.transcriptRing) t.lines.shift();
    }
    if (typeof b.draft === 'string') t.draft = b.draft;
    // A draft-only post bumps seq with no line attached. The page refetches the
    // transcript only when the counter moves, so without this a new draft would
    // sit here until some later tool call happened to move it - which for a
    // model that thinks for four minutes and then writes is precisely the wrong
    // moment. A delta fetch returning zero lines and a draft is fine.
    t.seq += 1;
    bump('health');
    return json(res, 200, { ok: true, seq: t.seq });
  });

  route('GET', '/api/run/transcript', async (req, res, url) => {
    const engine = url.searchParams.get('engine') || cfg.defaultEngine;
    const rawSince = url.searchParams.get('since');
    const since = rawSince === null ? 0 : clampInt(rawSince, 0, Number.MAX_SAFE_INTEGER, 0);
    const t = transcriptFor(engine);
    return json(res, 200, {
      runId: t.runId,
      seq: t.seq,
      lines: t.lines.filter((l) => l.seq > since),
      // Read off the LIVE run, so it vanishes the moment the run ends - which
      // is exactly when the real reply lands. A leftover draft sitting above a
      // finished reply reads as part of it.
      draft: state.activeRun ? t.draft : '',
    });
  });

  route('POST', '/api/run/kill', async (req, res) => {
    if (!state.activeRun) return json(res, 404, { error: 'no active run' });
    state.activeRun.killRequested = true;
    bump('health');
    return json(res, 200, { ok: true });
  });

  route('POST', '/api/run/end', async (req, res) => {
    state.activeRun = null;
    bump('health');
    return json(res, 200, { ok: true });
  });

  route('POST', '/api/run/failed', async (req, res) => {
    const b = await readJson(req);
    const reason = clampStr(b.reason, 2000) || 'unknown failure';
    // Persisted, because a run that takes the server down with it is exactly
    // when retry matters most.
    if (b.item && b.item.message) {
      state.lastFailed = {
        message: clampStr(b.item.message, 100000),
        thread: threads.normalize(b.item.thread),
        engine: clampStr(b.item.engine, 32),
        model: clampStr(b.item.model, 64),
        at: Date.now(),
        reason,
      };
    }
    state.activeRun = null;
    notifyInternal(`the watcher failed: ${reason}`);
    return json(res, 200, { ok: true });
  });

  // --- threads and context -----------------------------------------------

  route('GET', '/api/threads', async (req, res) => json(res, 200, { items: threads.list(paths), default: threads.DEFAULT_THREAD }));

  route('GET', '/api/handover', async (req, res, url) => {
    const t = threads.read(paths, url.searchParams.get('thread'));
    return json(res, 200, { thread: t.name, exists: t.exists, text: t.handover, hasSession: !!t.session });
  });

  route('POST', '/api/handover/clear', async (req, res) => {
    const b = await readJson(req);
    const name = threads.clear(paths, b.thread);
    bump('context');
    return json(res, 200, { ok: true, thread: name });
  });

  route('DELETE', '/api/threads', async (req, res, url) => {
    const ok = threads.remove(paths, url.searchParams.get('thread'));
    bump('context');
    return json(res, ok ? 200 : 400, ok ? { ok: true } : { error: 'cannot delete the default thread' });
  });

  // --- artifacts ---------------------------------------------------------

  route('GET', '/api/artifacts', async (req, res) => {
    let items = [];
    try {
      items = fs.readdirSync(paths.artifacts).map((name) => {
        const st = fs.statSync(path.join(paths.artifacts, name));
        return { name, size: st.size, at: st.mtimeMs };
      }).filter((f) => f.size >= 0).sort((a, b) => b.at - a.at);
    } catch (e) {
      items = [];
    }
    return json(res, 200, { items });
  });

  // --- health ------------------------------------------------------------

  route('GET', '/api/health', async (req, res) => {
    const now = Date.now();
    const queued = state.inbox.filter((i) => isDue(i, now)).length;
    return json(res, 200, {
      ok: true,
      version: require('../package.json').version,
      // A parked message showing up as plain "queued" reads as stuck, so the
      // two counts are separate.
      queued,
      scheduled: state.inbox.length - queued,
      notifications: state.notifications.length,
      lastFailed: state.lastFailed,
      activeRun: state.activeRun,
      // Counters only. The lines themselves ride on /api/run/transcript, for
      // the reason written above transcriptFor().
      transcript: Object.fromEntries(Object.entries(state.transcripts).map(([k, v]) => [k, { runId: v.runId, seq: v.seq }])),
      engines: Object.values(cfg.engines).map((e) => ({
        name: e.name, label: e.label, models: Object.keys(e.modelMap || {}), relay: !!e.supportsRelayHook,
      })),
      defaultEngine: cfg.defaultEngine,
      workspace: cfg.workspace,
      permissionMode: cfg.permissionMode,
      relay: { enabled: !!(cfg.relay && cfg.relay.enabled) },
      lock: lockmod.inspect(paths.lockDir, 'watch'),
      warnings: ctx.warnings,
      push: { available: !!ctx.pushKeys(), subscribers: ctx.pushSubs().length },
    });
  });

  // --- logs --------------------------------------------------------------

  route('GET', '/api/logs', async (req, res, url) => {
    const key = url.searchParams.get('file') || 'halyard';
    const file = LOG_FILES[key];
    if (!file) return json(res, 400, { error: `unknown log; one of ${Object.keys(LOG_FILES).join(', ')}` });
    const tail = clampInt(url.searchParams.get('tail'), 1, 2000, 200);
    let text = '';
    try {
      const st = fs.statSync(file);
      // Only the last 256KB. These files run to megabytes between rotations and
      // slurping one on a phone request is how a diagnostic tool becomes the
      // problem it was opened to diagnose.
      const want = Math.min(st.size, 256 * 1024);
      const fd = fs.openSync(file, 'r');
      const buf = Buffer.alloc(want);
      fs.readSync(fd, buf, 0, want, st.size - want);
      fs.closeSync(fd);
      text = buf.toString('utf8');
      // Drop the partial first line that starting mid-file produces.
      if (want < st.size) text = text.slice(text.indexOf('\n') + 1);
    } catch (e) {
      return json(res, 200, { file: key, lines: [], note: `not readable: ${e.message}` });
    }
    return json(res, 200, { file: key, lines: text.split('\n').filter(Boolean).slice(-tail) });
  });

  // --- push --------------------------------------------------------------

  route('GET', '/api/push/key', async (req, res) => {
    const keys = ctx.pushKeys();
    return json(res, 200, { publicKey: keys ? keys.publicKey : null });
  });

  route('POST', '/api/push/subscribe', async (req, res) => {
    const sub = await readJson(req);
    if (!sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
      return json(res, 400, { error: 'endpoint and keys are required' });
    }
    ctx.addPushSub({ endpoint: String(sub.endpoint), keys: { p256dh: String(sub.keys.p256dh), auth: String(sub.keys.auth) } });
    return json(res, 200, { ok: true });
  });

  route('POST', '/api/push/test', async (req, res) => {
    await deliver({ id: newId(), message: 'Halyard push is working.', thread: 'main', internal: true, kind: 'internal' });
    return json(res, 200, { ok: true, subscribers: ctx.pushSubs().length });
  });

  // --- config (redacted) -------------------------------------------------

  route('GET', '/api/config', async (req, res) => json(res, 200, {
    host: cfg.host,
    port: cfg.port,
    workspace: cfg.workspace,
    defaultEngine: cfg.defaultEngine,
    permissionMode: cfg.permissionMode,
    relay: cfg.relay,
    dataDir: paths.root,
    warnings: ctx.warnings,
  }));

  // messages.log: a human-readable tail of recent turns, rewritten rather than
  // appended so it stays small enough to open on a phone. It is NOT the durable
  // copy - replies.jsonl is - which is why truncating it here is safe.
  function writeMessageLog(entry) {
    try {
      const lines = readJsonl(paths.messages).slice(-19);
      lines.push({ at: entry.at, thread: entry.thread, prompt: entry.prompt, reply: clampStr(entry.message, 4000) });
      fs.writeFileSync(paths.messages, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
    } catch (e) {
      log.debug(`message log write failed: ${e.message}`);
    }
  }

  // ---------------------------------------------------------------------
  // Static assets

  const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.webp': 'image/webp',
    '.pdf': 'application/pdf',
    '.txt': 'text/plain; charset=utf-8',
  };

  function sendFile(res, file, { download = false, cache = 'no-cache' } = {}) {
    let st;
    try { st = fs.statSync(file); } catch (e) { return json(res, 404, { error: 'not found' }); }
    if (st.isDirectory()) return json(res, 404, { error: 'not found' });
    res.writeHead(200, {
      'content-type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'content-length': st.size,
      'cache-control': cache,
      'x-content-type-options': 'nosniff',
      ...(download ? { 'content-disposition': `attachment; filename="${path.basename(file)}"` } : {}),
    });
    fs.createReadStream(file).pipe(res);
  }

  // ---------------------------------------------------------------------
  // Request dispatch

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
    const p = url.pathname;

    // Everything is token-gated except the service worker, which has no token
    // to offer. That is the whole reason it is exempt, and the reason nothing
    // it precaches may be behind the gate - see public/sw.js.
    const supplied = url.searchParams.get('token')
      || (req.headers.authorization || '').replace(/^Bearer\s+/i, '')
      || (/(?:^|;\s*)halyard_token=([^;]+)/.exec(req.headers.cookie || '') || [])[1];

    if (p === '/sw.js') return sendFile(res, path.join(PUBLIC_DIR, 'sw.js'), { cache: 'no-cache' });

    if (!tokenMatches(supplied, token)) {
      res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' });
      return res.end('<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><style>body{font:16px system-ui;margin:3rem auto;max-width:32rem;padding:0 1rem;color:#222}code{background:#eee;padding:.15em .35em;border-radius:4px}</style><h1>Halyard</h1><p>This bridge needs a token.</p><p>Open the link printed by <code>halyard start</code>, or append <code>?token=…</code> from <code>halyard token</code>.</p>');
    }

    // Set the token as a cookie so in-page navigations and the manifest's
    // start_url survive without carrying it in every href.
    if (url.searchParams.get('token')) {
      res.setHeader('set-cookie', `halyard_token=${encodeURIComponent(token)}; Path=/; SameSite=Strict; Max-Age=31536000${req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : ''}`);
    }

    try {
      // --- change stream ---
      if (p === '/api/events') {
        res.writeHead(200, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
          connection: 'keep-alive',
          'x-accel-buffering': 'no',
        });
        res.write(`data: ${JSON.stringify(versions)}\n\n`);
        sseClients.add(res);
        // Comment frames keep intermediaries from closing an idle stream.
        const ka = setInterval(() => { try { res.write(': ka\n\n'); } catch (e) { /* closing */ } }, 25000);
        req.on('close', () => { clearInterval(ka); sseClients.delete(res); });
        return undefined;
      }

      // --- artifacts (GET and DELETE share one resolver) ---
      if (p.startsWith('/artifacts/')) {
        const file = resolveArtifact(p);
        if (!file) return json(res, 400, { error: 'bad artifact path' });
        if (req.method === 'DELETE') {
          try { fs.unlinkSync(file); } catch (e) { return json(res, 404, { error: 'not found' }); }
          bump('artifacts');
          return json(res, 200, { ok: true });
        }
        return sendFile(res, file, { cache: 'no-store' });
      }

      // --- uploads ---
      if (p === '/api/upload' && req.method === 'POST') {
        const name = (url.searchParams.get('name') || 'upload.bin').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128);
        const buf = await readBody(req, cfg.maxUploadBytes);
        const dest = path.join(paths.uploads, `${Date.now()}-${name}`);
        fs.writeFileSync(dest, buf);
        bump('artifacts');
        return json(res, 200, { ok: true, path: dest, bytes: buf.length });
      }

      // --- page shell ---
      if (p === '/' || p === '/index.html') return sendFile(res, path.join(PUBLIC_DIR, 'index.html'));
      if (p === '/icon.svg') return sendFile(res, path.join(PUBLIC_DIR, 'icon.svg'), { cache: 'public, max-age=86400' });
      if (p === '/manifest.json') {
        // Built here rather than served from disk because start_url has to
        // carry the token - a PWA launched from the home screen has no query
        // string of its own and would land on the 401 page.
        return json(res, 200, {
          name: 'Halyard', short_name: 'Halyard',
          start_url: `/?token=${encodeURIComponent(token)}`,
          display: 'standalone', background_color: '#0e1116', theme_color: '#0e1116',
          icons: [{ src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any maskable' }],
        });
      }

      const handler = routes[`${req.method} ${p}`];
      if (!handler) return json(res, 404, { error: 'no such route' });
      return await handler(req, res, url);
    } catch (e) {
      const status = e.status || 500;
      if (status >= 500) log.error(`${req.method} ${p} failed: ${e.stack || e.message}`);
      if (!res.headersSent) return json(res, status, { error: e.message });
      return res.end();
    }
  });

  loadState();
  watchDir(paths.threads, 'context');
  watchDir(paths.artifacts, 'artifacts');

  server.on('listening', () => log.info(`listening on http://${cfg.host}:${cfg.port}`));

  return {
    server,
    state,
    listen: () => new Promise((resolve) => server.listen(cfg.port, cfg.host, resolve)),
    close: () => new Promise((resolve) => {
      for (const c of sseClients) { try { c.end(); } catch (e) { /* closing anyway */ } }
      sseClients.clear();
      // Watchers and their pending debounce timers, or a closed server leaves
      // handles behind - which in a test suite that starts twenty of them is
      // the difference between exiting and appearing to hang.
      for (const { w, stop } of watchers) { try { stop(); w.close(); } catch (e) { /* already closed */ } }
      watchers.length = 0;
      server.close(resolve);
    }),
  };
}

module.exports = { createServer, nextOccurrence, isDue, tokenMatches, REPEATS, appendJsonl, readJsonl };
