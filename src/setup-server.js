// The setup page's own tiny server: 127.0.0.1 only, an ephemeral port, and its
// own one-time key, so it can run before (and beside) Halyard itself. It shows
// the checks from src/setup.js with a tick each, and offers the fixes that can
// be one click. It is gone the moment setup finishes.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const setup = require('./setup');
const qr = require('./qr');
const { createClient } = require('./client');

const PAGE = path.join(__dirname, '..', 'public', 'setup.html');

function json(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

// [deps] are injectable for the tests: run (child processes), installService
// (writes + registers the login service), startHalyard (spawns the server).
function createSetupServer({ boot, token, deps = {} }) {
  const { cfg, paths } = boot;
  const key = crypto.randomBytes(16).toString('base64url');
  const run = deps.run;
  const settingsPath = deps.settingsPath || setup.claudeSettingsPath();
  const tsOpts = deps.tailscaleBin !== undefined ? { run, bin: deps.tailscaleBin } : { run };
  let done = false;
  let onDone = () => {};

  async function health() {
    const c = createClient(cfg, token, { timeoutMs: 2000 });
    return c.tryGet('/api/health');
  }

  async function status() {
    const ts = setup.tailscaleState(cfg.port, tsOpts);
    const h = await health();
    const checks = setup.runChecks({ cfg, paths, health: h, run, settingsPath, tailscale: ts, readCreds: deps.readCreds });
    return {
      checks,
      running: !!h,
      tailscale: { installed: ts.installed, running: !!ts.running, url: ts.url || '', serving: !!ts.servesPort, download: setup.TAILSCALE_DOWNLOAD },
      pairingUrl: setup.pairingUrl(cfg, token, ts),
      service: (deps.serviceInstalled || setup.serviceInstalled)(),
      port: cfg.port,
    };
  }

  function saveConfig(patch) {
    let cur = {};
    try { cur = JSON.parse(fs.readFileSync(paths.config, 'utf8')); } catch (e) { cur = {}; }
    fs.writeFileSync(paths.config, `${JSON.stringify({ ...cur, ...patch }, null, 2)}\n`);
    Object.assign(cfg, patch);
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    // The key gates everything, the page included: another local user, or a
    // web page in this browser poking at localhost ports, must not be able to
    // rewrite the agent's settings.
    if (url.searchParams.get('key') !== key) return json(res, 403, { error: 'wrong setup key' });
    try {
      if (req.method === 'GET' && url.pathname === '/') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
        return res.end(fs.readFileSync(PAGE));
      }
      if (req.method === 'GET' && url.pathname === '/api/status') return json(res, 200, await status());
      if (req.method === 'GET' && url.pathname === '/api/qr.svg') {
        const s = await status();
        res.writeHead(200, { 'content-type': 'image/svg+xml', 'cache-control': 'no-store' });
        return res.end(qr.toSvg(qr.encode(s.pairingUrl, { ecl: 'M' }), { scale: 6 }));
      }
      if (req.method === 'GET' && url.pathname === '/api/hooks/preview') {
        const p = setup.previewHooks(settingsPath);
        return json(res, 200, { target: p.target, ok: p.ok, error: p.error, changed: p.changed, diff: p.diff });
      }
      if (req.method !== 'POST') return json(res, 404, { error: 'no such route' });

      if (url.pathname === '/api/hooks/apply') {
        const r = setup.installHooks(settingsPath);
        return json(res, r.ok ? 200 : 400, { ok: r.ok, error: r.error, written: r.written, backup: r.backup, target: r.target });
      }
      if (url.pathname === '/api/tailscale/serve') {
        const r = setup.tailscaleServe(cfg.port, tsOpts);
        // The phone's link is the tunnel's address from now on, and every
        // notification and QR code should carry it.
        if (r.ok && r.url) saveConfig({ publicUrl: r.url });
        return json(res, r.ok ? 200 : 400, r);
      }
      if (url.pathname === '/api/service/install') {
        const r = await (deps.installService || (async () => ({ ok: false, error: 'not available' })))();
        return json(res, r.ok ? 200 : 400, r);
      }
      if (url.pathname === '/api/start') {
        if (await health()) return json(res, 200, { ok: true, already: true });
        const r = await (deps.startHalyard || defaultStart)(boot);
        return json(res, r.ok ? 200 : 400, r);
      }
      if (url.pathname === '/api/done') {
        done = true;
        json(res, 200, { ok: true });
        return onDone();
      }
      return json(res, 404, { error: 'no such route' });
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  });

  return {
    server,
    key,
    status,
    listen: () => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}/?key=${key}`))),
    waitDone: () => new Promise((resolve) => { if (done) resolve(); else onDone = resolve; }),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// Halyard in the background, outliving setup, logging to its data dir. The
// login service is the durable way; this is "so the phone can try it now".
function defaultStart(boot) {
  const out = fs.openSync(path.join(boot.paths.root, 'halyard.out.log'), 'a');
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'halyard.js'), 'start', '--data-dir', boot.paths.root],
    { detached: true, stdio: ['ignore', out, out], windowsHide: true });
  child.unref();
  return new Promise((resolve) => setTimeout(() => resolve({ ok: true, pid: child.pid }), 1500));
}

module.exports = { createSetupServer };
