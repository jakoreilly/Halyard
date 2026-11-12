// Everything `halyard setup` and `halyard doctor` need to tell a person, in
// plain words, whether this machine is ready - and to fix what can be fixed
// with one click.
//
// Two rules shape this file:
//
//   Every check says what to DO, not just what is wrong. A check that reports
//   "hooks: missing" to someone who has never heard of a hook is a dead end.
//   Each one carries a one-line `fix` written for that person.
//
//   Anything that changes the machine (the agent's settings file, a tunnel, a
//   login service) is a separate action the person asks for, shown first
//   (a diff, the exact command) and reversible (a backup, a printed undo).
//   Nothing here changes anything just by being looked at.
//
// Every outside call goes through an injectable `run`, so the tests exercise
// all of it without a real Tailscale, launchctl or agent CLI.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { resolveCommand, whichSync } = require('./which');
const usagemod = require('./usage');

const ROOT = path.join(__dirname, '..');
const HOOKS_DIR = path.join(ROOT, 'hooks');

// Which tools reach hooks/permission-relay.js. Must cover every tool in its
// RELAYED_TOOLS (shell tools) plus the read tools that taint a run -
// test/smoke.js asserts the two agree.
const RELAY_MATCHER = 'Bash|PowerShell|WebFetch|WebSearch|Read|mcp__.*';

function defaultRun(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: opts.timeout || 15000, windowsHide: true, ...opts });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || (r.error ? r.error.message : '') };
}

// --- hook wiring -------------------------------------------------------------

// The PreToolUse entries Halyard needs. `node "<path>"` so a path with spaces
// survives the agent's own shell.
function hookEntries(hooksDir = HOOKS_DIR) {
  return [
    {
      // MUST name every tool that can run a shell, not just Bash, plus the read
      // tools that arm the relay's tainted-egress rule.
      matcher: RELAY_MATCHER,
      hooks: [{ type: 'command', command: `node "${path.join(hooksDir, 'permission-relay.js')}"` }],
    },
    {
      // `*`: a run that only edits files makes no shell call and would
      // otherwise never receive a steer from the phone.
      matcher: '*',
      hooks: [{ type: 'command', command: `node "${path.join(hooksDir, 'nudge-inject.js')}"` }],
    },
  ];
}

// Claude Code's user settings. CLAUDE_CONFIG_DIR moves the whole folder.
function claudeSettingsPath(env = process.env, home = os.homedir()) {
  return path.join(env.CLAUDE_CONFIG_DIR || path.join(home, '.claude'), 'settings.json');
}

// A hook command is Halyard's if it runs one of Halyard's two hook scripts from
// THIS install, or from any folder with "halyard" in its path (an older copy) -
// never someone else's hook that happens to share a file name.
function isOurHook(command, hooksDir = HOOKS_DIR) {
  const c = String(command || '');
  if (!/(permission-relay|nudge-inject)\.js/.test(c)) return false;
  return c.includes(hooksDir) || /halyard/i.test(c);
}

// -> { next, changed }. Pure: the caller decides whether to write. Every hook
// that is not Halyard's is kept exactly where it was.
function mergeHooks(existing, hooksDir = HOOKS_DIR) {
  const next = existing && typeof existing === 'object' && !Array.isArray(existing) ? JSON.parse(JSON.stringify(existing)) : {};
  if (!next.hooks || typeof next.hooks !== 'object') next.hooks = {};
  const pre = Array.isArray(next.hooks.PreToolUse) ? next.hooks.PreToolUse : [];
  const kept = [];
  for (const entry of pre) {
    const hooks = Array.isArray(entry && entry.hooks) ? entry.hooks.filter((h) => !isOurHook(h && h.command, hooksDir)) : [];
    if (hooks.length) kept.push({ ...entry, hooks });
    else if (!Array.isArray(entry && entry.hooks)) kept.push(entry);
  }
  next.hooks.PreToolUse = kept.concat(hookEntries(hooksDir));
  return { next, changed: JSON.stringify(next) !== JSON.stringify(existing || {}) };
}

// A plain line diff (LCS), enough to show someone exactly what will change in
// their settings file before it does.
function lineDiff(a, b) {
  const x = String(a).split('\n');
  const y = String(b).split('\n');
  const n = x.length; const m = y.length;
  const L = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = x[i] === y[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const out = [];
  let i = 0; let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && x[i] === y[j]) { out.push(`  ${x[i]}`); i++; j++; } else if (j < m && (i >= n || L[i][j + 1] >= L[i + 1][j])) { out.push(`+ ${y[j]}`); j++; } else { out.push(`- ${x[i]}`); i++; }
  }
  return out.join('\n');
}

function readJsonFile(file) {
  if (!fs.existsSync(file)) return { exists: false, value: {} };
  const raw = fs.readFileSync(file, 'utf8');
  if (!raw.trim()) return { exists: true, value: {} };
  return { exists: true, value: JSON.parse(raw) }; // throws on a broken file - see previewHooks
}

function previewHooks(target = claudeSettingsPath(), hooksDir = HOOKS_DIR) {
  let current;
  try { current = readJsonFile(target); } catch (e) {
    return { target, ok: false, error: `${target} is not valid JSON (${e.message}). Fix or move it, then try again - Halyard will not overwrite a file it cannot read.` };
  }
  const { next, changed } = mergeHooks(current.value, hooksDir);
  const before = current.exists ? JSON.stringify(current.value, null, 2) : '';
  const after = JSON.stringify(next, null, 2);
  return { target, ok: true, exists: current.exists, changed, next, diff: changed ? lineDiff(before, after) : '' };
}

// Writes the merged settings, after a timestamped backup of whatever was there.
function installHooks(target = claudeSettingsPath(), { hooksDir = HOOKS_DIR, now = Date.now() } = {}) {
  const p = previewHooks(target, hooksDir);
  if (!p.ok) return p;
  if (!p.changed) return { ...p, written: false };
  fs.mkdirSync(path.dirname(target), { recursive: true });
  let backup = null;
  if (p.exists) {
    backup = `${target}.halyard-backup-${new Date(now).toISOString().replace(/[:.]/g, '-')}`;
    fs.copyFileSync(target, backup);
  }
  const tmp = `${target}.halyard-tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(p.next, null, 2)}\n`);
  fs.renameSync(tmp, target);
  return { ...p, written: true, backup };
}

function hooksWired(target = claudeSettingsPath(), hooksDir = HOOKS_DIR) {
  try {
    const { value } = readJsonFile(target);
    const pre = (value.hooks && value.hooks.PreToolUse) || [];
    const has = (file, matcher) => pre.some((e) => e && e.matcher === matcher && (e.hooks || []).some((h) => String(h.command || '').includes(path.join(hooksDir, file))));
    return has('permission-relay.js', RELAY_MATCHER) && has('nudge-inject.js', '*');
  } catch (e) {
    return false;
  }
}

// --- Tailscale ---------------------------------------------------------------

const TAILSCALE_DOWNLOAD = 'https://tailscale.com/download';

function findTailscale({ env = process.env, platform = process.platform, exists = fs.existsSync } = {}) {
  const onPath = whichSync('tailscale', env, platform);
  if (onPath) return onPath;
  const candidates = platform === 'darwin' ? ['/Applications/Tailscale.app/Contents/MacOS/Tailscale']
    : platform === 'win32' ? [path.join(env.ProgramFiles || 'C:\\Program Files', 'Tailscale', 'tailscale.exe')] : [];
  return candidates.find((c) => exists(c)) || null;
}

// The https address `tailscale serve status` shows proxying to this port, and
// whether it already proxies anything ELSE - in which case Halyard must not
// take the default 443 address over from it.
function parseServeStatus(text, port) {
  const t = String(text || '');
  const lines = t.split('\n');
  let current = '';
  let url = '';
  let other = false;
  for (const line of lines) {
    const head = /^(https?:\/\/\S+?)\/?\s/.exec(`${line.trim()} `);
    if (head && !/proxy/.test(line)) current = head[1];
    const proxy = /proxy\s+https?:\/\/(?:127\.0\.0\.1|localhost):(\d+)/.exec(line);
    if (proxy) {
      if (Number(proxy[1]) === Number(port)) url = url || current;
      else other = true;
    }
  }
  return { url, other };
}

// -> { installed, running, dnsName, url, servesPort, servesOther }
function tailscaleState(port, { run = defaultRun, bin = findTailscale() } = {}) {
  if (!bin) return { installed: false, running: false };
  const st = run(bin, ['status', '--json']);
  let j = null;
  try { j = JSON.parse(st.stdout); } catch (e) { j = null; }
  const running = !!(j && j.BackendState === 'Running');
  const dnsName = j && j.Self && j.Self.DNSName ? String(j.Self.DNSName).replace(/\.$/, '') : '';
  let serve = { url: '', other: false };
  if (running) {
    const s = run(bin, ['serve', 'status']);
    serve = parseServeStatus(`${s.stdout}\n${s.stderr}`, port);
  }
  const url = serve.url || (dnsName ? `https://${dnsName}` : '');
  return { installed: true, bin, running, dnsName, url, servesPort: !!serve.url, servesOther: serve.other };
}

// `tailscale serve --bg <port>`: HTTPS on the tailnet name, proxied to the
// loopback port. Only reachable from your own tailnet devices.
function tailscaleServe(port, { run = defaultRun, bin = findTailscale() } = {}) {
  if (!bin) return { ok: false, error: `Tailscale is not installed. Get it from ${TAILSCALE_DOWNLOAD}, sign in, then try again.` };
  // Something else already owns this machine's tailnet https address: put
  // Halyard beside it on 8443 rather than silently replacing it.
  const before = tailscaleState(port, { run, bin });
  const https = before.servesOther ? 8443 : 443;
  const args = https === 443 ? ['serve', '--bg', String(port)] : ['serve', '--bg', `--https=${https}`, String(port)];
  const r = run(bin, args, { timeout: 30000 });
  if (r.status !== 0) {
    const why = (r.stderr || r.stdout || '').trim().split('\n').slice(-2).join(' ');
    return { ok: false, error: `tailscale serve failed: ${why || `exit ${r.status}`}` };
  }
  const st = tailscaleState(port, { run, bin });
  // The status listing is the truth when it shows this port; otherwise build
  // the address from the name and the port just asked for, never the bare
  // name (which, at 8443, is the OTHER service).
  const url = st.servesPort ? st.url : (st.dnsName ? `https://${st.dnsName}${https === 443 ? '' : `:${https}`}` : '');
  return { ok: true, url, https, undo: `${bin} serve --https=${https} off` };
}

// --- start on login ------------------------------------------------------------

// The commands that register the unit `halyard install-service` wrote. Run
// only when the person said yes; printed either way.
function registerCommands(platform, unitFile, home = os.homedir()) {
  if (platform === 'darwin') {
    const dest = path.join(home, 'Library', 'LaunchAgents', 'com.halyard.bridge.plist');
    return {
      copyTo: dest,
      cmds: [['launchctl', ['unload', dest], { ignoreFailure: true }], ['launchctl', ['load', '-w', dest]]],
      undo: `launchctl unload -w "${dest}" && rm "${dest}"`,
    };
  }
  if (platform === 'win32') {
    return { copyTo: null, cmds: [['powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', unitFile]]], undo: 'Unregister-ScheduledTask -TaskName Halyard -Confirm:$false' };
  }
  const dest = path.join(home, '.config', 'systemd', 'user', 'halyard.service');
  return {
    copyTo: dest,
    cmds: [['systemctl', ['--user', 'daemon-reload']], ['systemctl', ['--user', 'enable', '--now', 'halyard']]],
    undo: 'systemctl --user disable --now halyard',
  };
}

function registerService(platform, unitFile, { run = defaultRun, home = os.homedir() } = {}) {
  const plan = registerCommands(platform, unitFile, home);
  if (plan.copyTo) {
    fs.mkdirSync(path.dirname(plan.copyTo), { recursive: true });
    fs.copyFileSync(unitFile, plan.copyTo);
  }
  for (const [cmd, args, o] of plan.cmds) {
    const r = run(cmd, args);
    if (r.status !== 0 && !(o && o.ignoreFailure)) return { ok: false, error: `${cmd} ${args.join(' ')} failed: ${(r.stderr || r.stdout).trim()}`, undo: plan.undo };
  }
  return { ok: true, undo: plan.undo };
}

function serviceInstalled(platform = process.platform, home = os.homedir(), { run = defaultRun } = {}) {
  if (platform === 'darwin') return fs.existsSync(path.join(home, 'Library', 'LaunchAgents', 'com.halyard.bridge.plist'));
  if (platform === 'win32') return run('schtasks', ['/Query', '/TN', 'Halyard']).status === 0;
  return fs.existsSync(path.join(home, '.config', 'systemd', 'user', 'halyard.service'));
}

// --- the checks ------------------------------------------------------------------

function agentSignedIn(engine, env = process.env, readCreds = usagemod.readCredentials) {
  if (!engine || engine.stream !== 'claude-json') return { known: false };
  if (env.ANTHROPIC_API_KEY) return { known: true, ok: true, how: 'API key in the environment' };
  try {
    const c = readCreds();
    const o = (c && (c.claudeAiOauth || c.oauth)) || {};
    return { known: true, ok: !!(o.accessToken || o.access_token), how: 'Claude sign-in' };
  } catch (e) {
    return { known: true, ok: false };
  }
}

// The six steps a person needs, each with a plain-language fix.
// [opts.health] is the running server's /api/health, or null if it is not up.
function runChecks({ cfg, paths, health = null, env = process.env, run = defaultRun, settingsPath = claudeSettingsPath(env), tailscale, readCreds } = {}) {
  const out = [];
  const add = (id, label, ok, detail, fix) => out.push({ id, label, ok: !!ok, detail: detail || '', fix: ok ? '' : fix });

  const [maj, min] = process.versions.node.split('.').map(Number);
  add('node', 'Node.js is installed', maj > 18 || (maj === 18 && min >= 17), `version ${process.versions.node}`,
    'Install Node.js 18.17 or newer from https://nodejs.org, then run setup again.');

  const engine = cfg.engines[cfg.defaultEngine];
  const r = resolveCommand(engine && engine.command);
  const signed = r.command ? agentSignedIn(engine, env, readCreds) : { known: false };
  add('agent', `${(engine && engine.label) || cfg.defaultEngine} is installed${signed.known ? ' and signed in' : ''}`,
    r.command && (!signed.known || signed.ok),
    r.command ? (signed.known ? (signed.ok ? `${r.command} (${signed.how})` : `${r.command}, but not signed in`) : r.command) : r.problem,
    !r.command
      ? (engine && engine.stream === 'claude-json' ? 'Install Claude Code (https://docs.claude.com/en/docs/claude-code), open a terminal, type claude and sign in.' : `Install ${cfg.defaultEngine}, or set its full path in the config's engines section.`)
      : 'Open a terminal, type claude, and sign in when it asks. Then run setup again.');

  add('token', 'Your private link is made', fs.existsSync(paths.token), '', 'Run halyard setup - it makes the link for you.');

  const wired = engine && engine.supportsRelayHook ? hooksWired(settingsPath) : true;
  add('hooks', 'Approve/deny on the phone is wired up', wired,
    engine && engine.supportsRelayHook ? settingsPath : 'this agent has no hooks to wire',
    'In setup, press "Wire it up" (it backs up your agent settings first), or run: halyard hook-config --install');

  const ts = tailscale || tailscaleState(cfg.port, { run });
  const publicOk = /^https:\/\//.test(cfg.publicUrl || '');
  let tunnelOk = ts.running && ts.servesPort;
  let tunnelFix = '';
  if (!ts.installed) tunnelFix = `Install Tailscale on this computer AND your phone, and sign in to both with the same account: ${TAILSCALE_DOWNLOAD}`;
  else if (!ts.running) tunnelFix = 'Open Tailscale on this computer and sign in.';
  else if (!ts.servesPort) tunnelFix = `In setup, press "Turn on the tunnel", or run: tailscale serve --bg ${ts.servesOther ? '--https=8443 ' : ''}${cfg.port}`;
  if (!tunnelOk && publicOk && !ts.installed) { tunnelOk = true; tunnelFix = ''; } // another tunnel (Cloudflare etc.), configured by hand
  add('tunnel', 'Your phone can reach this computer', tunnelOk,
    tunnelOk ? (ts.url || cfg.publicUrl) : (ts.installed ? (ts.running ? 'Tailscale is on, but not serving Halyard' : 'Tailscale is installed but not signed in') : 'Tailscale not found'),
    tunnelFix);

  const paired = !!(health && (health.paired || (health.push && health.push.subscribers > 0)));
  add('phone', 'Your phone has opened Halyard', paired,
    health ? (paired ? 'seen' : 'not yet') : 'Halyard is not running',
    health ? 'Scan the QR code with your phone camera and open the link (same Wi-Fi is not needed - Tailscale handles it).' : 'Start Halyard (setup can do it, or run: halyard start), then scan the QR code.');

  return out;
}

// The link the phone should open: the tunnel's https URL when there is one.
function pairingUrl(cfg, token, ts) {
  const base = (cfg.publicUrl || (ts && ts.servesPort && ts.url) || `http://127.0.0.1:${cfg.port}`).replace(/\/+$/, '');
  return `${base}/?token=${encodeURIComponent(token)}`;
}

function openBrowser(url, { platform = process.platform, spawnImpl = require('child_process').spawn } = {}) {
  const [cmd, args] = platform === 'darwin' ? ['open', [url]]
    : platform === 'win32' ? ['cmd', ['/c', 'start', '""', url]] : ['xdg-open', [url]];
  try {
    const p = spawnImpl(cmd, args, { stdio: 'ignore', detached: true, windowsHide: true });
    p.on('error', () => {});
    p.unref();
    return true;
  } catch (e) {
    return false;
  }
}

// Whether a browser can be opened from here at all: a terminal session on a
// desktop. Over SSH, or on a headless Linux box, the terminal steps are used.
function canOpenBrowser(env = process.env, platform = process.platform, isTTY = !!process.stdout.isTTY) {
  if (!isTTY || env.SSH_CONNECTION || env.CI) return false;
  if (platform === 'darwin' || platform === 'win32') return true;
  return !!(env.DISPLAY || env.WAYLAND_DISPLAY);
}

module.exports = {
  RELAY_MATCHER, HOOKS_DIR, TAILSCALE_DOWNLOAD,
  hookEntries, claudeSettingsPath, isOurHook, mergeHooks, lineDiff, previewHooks, installHooks, hooksWired,
  findTailscale, tailscaleState, tailscaleServe, parseServeStatus,
  registerCommands, registerService, serviceInstalled,
  agentSignedIn, runChecks, pairingUrl, openBrowser, canOpenBrowser,
};
