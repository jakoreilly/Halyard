#!/usr/bin/env node
// The one entry point. Every command is a subcommand of this file so that
// "how do I run it" has exactly one answer on every platform, rather than a
// .cmd here, a .sh there and a scheduled task somewhere else.
//
//   halyard setup     interactive-ish first run: config, token, push keys
//   halyard start     server + built-in watcher (this is the normal command)
//   halyard serve     server only, for when the watcher runs elsewhere
//   halyard watch     one watcher pass, for a cron/systemd timer
//   halyard doctor    what is configured, what is reachable, what is risky
//   halyard token     print the token, or the full tokened URL
//   halyard install-service   write a service unit for this OS
//   halyard hook-config       print the agent hook config to paste in

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const pathsmod = require('../src/paths');
const configmod = require('../src/config');
const { createLogger } = require('../src/log');
const { createServer } = require('../src/server');
const { createClient } = require('../src/client');
const { writeFileAtomic } = require('../src/atomic');
const watcher = require('../src/watcher');
const pushmod = require('../src/push');
const lockmod = require('../src/lock');
const { whichSync, resolveCommand } = require('../src/which');

const setup = require('../src/setup');
const qr = require('../src/qr');

const pkg = require('../package.json');

const { RELAY_MATCHER } = setup;

// ---------------------------------------------------------------------------
// Argument parsing. Deliberately tiny: --key value, --flag, and positionals.

function parseArgv(argv) {
  const out = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const eq = a.indexOf('=');
    if (eq !== -1) { out.flags[a.slice(2, eq)] = a.slice(eq + 1); continue; }
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) { out.flags[a.slice(2)] = true; continue; }
    out.flags[a.slice(2)] = next;
    i += 1;
  }
  return out;
}

// Flags that map onto config keys, so `halyard start --port 5000` works without
// editing a file. Everything else in config is file-or-env only, on purpose:
// a flag for every setting is a CLI nobody can read.
function cliOverrides(flags) {
  const cli = {};
  if (flags.port) cli.port = Number(flags.port);
  if (flags.host) cli.host = String(flags.host);
  if (flags.workspace) cli.workspace = String(flags.workspace);
  if (flags.engine) cli.defaultEngine = String(flags.engine);
  if (flags['permission-mode']) cli.permissionMode = String(flags['permission-mode']);
  if (flags['public-url']) cli.publicUrl = String(flags['public-url']);
  if (flags['no-relay']) cli.relay = { enabled: false };
  return cli;
}

// ---------------------------------------------------------------------------
// Bootstrap shared by every command that needs a live configuration

function bootstrap(argv) {
  const dataDir = argv.flags['data-dir']
    ? path.resolve(String(argv.flags['data-dir']))
    : pathsmod.defaultDataDir();
  const paths = pathsmod.ensure(pathsmod.layout(dataDir));

  const warnings = [];
  const cfg = configmod.load({
    file: paths.config,
    cli: cliOverrides(argv.flags),
    warn: (m) => warnings.push({ level: 'warn', msg: m }),
  });
  const log = createLogger(paths.log, cfg.logLevel);
  warnings.push(...configmod.audit(cfg));

  return { dataDir, paths, cfg, log, warnings };
}

// A token is 32 bytes of CSPRNG, base64url. Created once at setup and never
// rotated automatically: it is baked into the PWA's start_url and into every
// notification payload already delivered, so rotating it silently would log the
// phone out with no explanation. `halyard token --rotate` is explicit.
function ensureToken(paths, { rotate = false } = {}) {
  if (!rotate && fs.existsSync(paths.token)) {
    const t = fs.readFileSync(paths.token, 'utf8').trim();
    if (t) return t;
  }
  const t = crypto.randomBytes(24).toString('base64url');
  fs.writeFileSync(paths.token, t, { mode: 0o600 });
  try { fs.chmodSync(paths.token, 0o600); } catch (e) { /* no-op on Windows */ }
  return t;
}

function ensurePushKeys(paths) {
  try {
    const k = JSON.parse(fs.readFileSync(paths.pushKeys, 'utf8'));
    if (k && k.publicKey && k.privateKey) return k;
  } catch (e) { /* generate below */ }
  const keys = pushmod.generateVapidKeys();
  fs.writeFileSync(paths.pushKeys, JSON.stringify(keys), { mode: 0o600 });
  return keys;
}

function readPushSubs(paths) {
  try {
    const s = JSON.parse(fs.readFileSync(paths.pushSubs, 'utf8'));
    return Array.isArray(s) ? s : [];
  } catch (e) {
    return [];
  }
}

function writePushSubs(paths, subs) {
  try { writeFileAtomic(paths.pushSubs, JSON.stringify(subs)); } catch (e) { /* best effort */ }
}

// ---------------------------------------------------------------------------
// Commands

async function cmdSetup(argv) {
  const { paths, cfg, dataDir } = bootstrap(argv);
  const token = ensureToken(paths);
  ensurePushKeys(paths);

  if (!fs.existsSync(paths.config)) {
    // Written with the resolved values rather than an empty object, so the
    // first thing someone opens is a file that shows what the defaults
    // actually were on their machine - not a file full of nulls.
    const seed = {
      host: cfg.host,
      port: cfg.port,
      publicUrl: cfg.publicUrl,
      defaultEngine: cfg.defaultEngine,
      workspace: cfg.workspace,
      permissionMode: cfg.permissionMode,
      relay: cfg.relay,
      push: cfg.push,
      ntfy: cfg.ntfy,
    };
    fs.writeFileSync(paths.config, `${JSON.stringify(seed, null, 2)}\n`);
  }

  console.log(`\n  Halyard ${pkg.version}: your settings are in ${dataDir}\n`);

  // The browser page is the easy path; the terminal steps are the same checks
  // and the same fixes, for SSH sessions, headless boxes and anyone who asks.
  if (!argv.flags['no-browser'] && setup.canOpenBrowser()) {
    const boot = bootstrap(argv);
    const srv = require('../src/setup-server').createSetupServer({
      boot,
      token,
      deps: { installService: () => installService(boot, { register: true }) },
    });
    const url = await srv.listen();
    const opened = setup.openBrowser(url);
    console.log(opened ? '  The setup page is open in your browser.' : '  Open this in your browser to continue:');
    console.log(`  ${url}\n`);
    console.log('  (Press Finish on the page, or Ctrl+C here, when you are done.)\n');
    await Promise.race([srv.waitDone(), new Promise((r) => process.once('SIGINT', r))]);
    await srv.close();
    console.log('\n  Setup finished. Run `halyard doctor` any time to re-check.\n');
    return;
  }
  await terminalSetup(bootstrap(argv), token);
}

function askYesNo(question) {
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(`  ${question} [y/N] `, (a) => { rl.close(); resolve(/^y(es)?$/i.test(a.trim())); }));
}

function printChecks(checks) {
  for (const c of checks) {
    console.log(`  ${c.ok ? '\u2713' : '\u2717'}  ${c.label}${c.detail ? `  (${c.detail})` : ''}`);
    if (!c.ok && c.fix) console.log(`       Fix: ${c.fix}`);
  }
}

async function terminalSetup(boot, token) {
  const { cfg, paths } = boot;
  const health = await createClient(cfg, token, { timeoutMs: 2000 }).tryGet('/api/health');
  let checks = setup.runChecks({ cfg, paths, health });
  printChecks(checks);
  console.log('');
  const failing = (id) => checks.some((c) => c.id === id && !c.ok);

  if (failing('hooks')) {
    const p = setup.previewHooks();
    if (!p.ok) console.log(`  ${p.error}\n`);
    else {
      console.log(`  Approve/deny needs two lines in ${p.target}. This is the change (a backup is made first):\n`);
      console.log(p.diff.split('\n').map((l) => `    ${l}`).join('\n'));
      if (await askYesNo('Make this change?')) {
        const r = setup.installHooks(p.target);
        console.log(r.ok ? `  Done.${r.backup ? ` Old settings saved to ${r.backup}` : ''}\n` : `  ${r.error}\n`);
      } else console.log('  Skipped. Run `halyard hook-config --install` later.\n');
    }
  }
  if (failing('tunnel')) {
    const ts = setup.tailscaleState(cfg.port);
    if (ts.installed && ts.running) {
      if (await askYesNo(`Turn on the Tailscale tunnel (runs: tailscale serve --bg ${cfg.port})?`)) {
        const r = setup.tailscaleServe(cfg.port);
        if (r.ok && r.url) {
          writeConfigPatch(paths, { publicUrl: r.url });
          cfg.publicUrl = r.url;
        }
        console.log(r.ok ? `  Done: ${r.url}  (undo: ${r.undo})\n` : `  ${r.error}\n`);
      }
    } else {
      console.log(`  To reach this computer from your phone, install Tailscale on both and sign in: ${setup.TAILSCALE_DOWNLOAD}\n`);
    }
  }
  if (!setup.serviceInstalled() && await askYesNo('Start Halyard by itself when you log in?')) {
    const r = await installService(boot, { register: true });
    console.log(r.ok ? `  Done. To undo: ${r.undo}\n` : `  ${r.error}\n`);
  }

  const ts = setup.tailscaleState(cfg.port);
  const link = setup.pairingUrl(cfg, token, ts);
  console.log('  Scan this with your phone camera (the link is private - treat it like a password):\n');
  console.log(qr.toTerminal(qr.encode(link, { ecl: 'M' })));
  console.log(`\n  ${link}\n`);
  if (!health) console.log('  Then start it:  halyard start\n');
  checks = setup.runChecks({ cfg, paths, health });
  const left = checks.filter((c) => !c.ok).length;
  console.log(left ? `  ${left} step(s) left - run \`halyard doctor\` for the fixes.\n` : '  All set.\n');
}

function writeConfigPatch(paths, patch) {
  let cur = {};
  try { cur = JSON.parse(fs.readFileSync(paths.config, 'utf8')); } catch (e) { cur = {}; }
  fs.writeFileSync(paths.config, `${JSON.stringify({ ...cur, ...patch }, null, 2)}\n`);
}

function serverContext(boot, token) {
  const { paths, cfg, log, warnings } = boot;
  let subs = readPushSubs(paths);
  let keys = null;
  try { keys = JSON.parse(fs.readFileSync(paths.pushKeys, 'utf8')); } catch (e) { keys = null; }

  const ctx = {
    cfg,
    paths,
    log,
    token,
    warnings,
    pushKeys: () => keys,
    pushSubs: () => subs,
    addPushSub: (sub) => {
      const prev = subs.find((s) => s.endpoint === sub.endpoint);
      // Re-subscribing the same browser must not reset when it was first seen.
      const merged = { ...sub, addedAt: (prev && prev.addedAt) || sub.addedAt || Date.now() };
      subs = subs.filter((s) => s.endpoint !== sub.endpoint).concat(merged);
      writePushSubs(paths, subs);
    },
    removePushSub: (endpoint) => {
      subs = subs.filter((s) => s.endpoint !== endpoint);
      writePushSubs(paths, subs);
    },
    // Replaced by cmdStart when a watcher is attached. A serve-only process has
    // no watcher to nudge, and calling a missing one must not 500 the queue
    // route that a phone is waiting on.
    nudge: () => {},
  };
  return ctx;
}

async function cmdStart(argv, { withWatcher = true } = {}) {
  const boot = bootstrap(argv);
  const { paths, cfg, log } = boot;
  const token = ensureToken(paths);
  ensurePushKeys(paths);

  const ctx = serverContext(boot, token);
  const app = createServer(ctx);

  let loop = null;
  if (withWatcher) {
    const client = createClient(cfg, token);
    loop = watcher.startLoop({ cfg, paths, log, client });
    ctx.nudge = () => loop.nudge();
  }

  await app.listen();

  const url = `http://${cfg.host === '0.0.0.0' ? '127.0.0.1' : cfg.host}:${cfg.port}/?token=${token}`;
  console.log(`\n  Halyard ${pkg.version}`);
  console.log(`  ${url}`);
  console.log(`  workspace  ${cfg.workspace}`);
  console.log(`  engine     ${cfg.defaultEngine}${withWatcher ? '' : '   (watcher NOT running in this process)'}`);
  if (cfg.publicUrl) console.log(`  public     ${cfg.publicUrl}/?token=${token}`);
  for (const w of boot.warnings) console.log(`  ${w.level === 'warn' ? '!' : 'i'}  ${w.msg}`);
  console.log('');

  const shutdown = async () => {
    console.log('\n  stopping…');
    if (loop) loop.stop();
    await app.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

// One pass, for a cron job or a systemd timer on a machine where the server
// runs somewhere else (a container, another user). Exits 0 whether or not there
// was anything to do - a timer that logs a failure on every idle tick trains
// people to ignore it.
async function cmdWatch(argv) {
  const boot = bootstrap(argv);
  const { paths, cfg, log } = boot;
  const token = ensureToken(paths);
  const client = createClient(cfg, token);
  const did = await watcher.runOnce({ cfg, paths, log, client });
  console.log(did ? 'processed one message' : 'nothing to do');
}

async function cmdDoctor(argv) {
  const boot = bootstrap(argv);
  const { paths, cfg, dataDir, warnings } = boot;
  const token = fs.existsSync(paths.token) ? fs.readFileSync(paths.token, 'utf8').trim() : '';

  const line = (k, v) => console.log(`  ${String(k).padEnd(16)} ${v}`);
  console.log(`\n  Halyard ${pkg.version}   node ${process.version}   ${process.platform}/${process.arch}\n`);
  line('data dir', dataDir);
  line('config', fs.existsSync(paths.config) ? paths.config : `${paths.config}  (absent, using defaults)`);
  line('token', token ? 'present' : 'MISSING - run: halyard setup');
  line('workspace', `${cfg.workspace}${fs.existsSync(cfg.workspace) ? '' : '  (does not exist)'}`);
  line('bind', `${cfg.host}:${cfg.port}`);
  line('permission mode', cfg.permissionMode);
  line('relay', cfg.relay.enabled ? `on (${cfg.relay.rules.join(', ')})` : 'OFF');

  console.log('\n  Engines');
  const engineHints = [];
  for (const e of Object.values(cfg.engines)) {
    // The same resolver the watcher uses, so this line is what will actually
    // be spawned rather than a second opinion about it. The old code stopped
    // at "found on PATH", which reported a Windows .CMD shim as healthy right
    // up until the run failed with ENOENT.
    const r = resolveCommand(e.command);
    const mark = e.name === cfg.defaultEngine ? '*' : ' ';
    const relay = e.supportsRelayHook ? '' : '   [no pre-tool hook: relay cannot arm]';
    // 'path' is the unremarkable case and says nothing; the other two mean the
    // configured command is not the thing being run, which is worth seeing.
    const via = r.command && r.source !== 'path' ? `   [via ${r.source}]` : '';
    console.log(`  ${mark} ${e.name.padEnd(10)} ${r.command ? `${r.command}${via}` : r.problem}${relay}`);
    if (!r.command && r.hint && e.name === cfg.defaultEngine) {
      engineHints.push(`${e.name}: ${r.hint}`);
    }
  }

  console.log('\n  Runtime');
  const held = lockmod.inspect(paths.lockDir, 'watch');
  line('run lock', held ? `held by pid ${held.pid} for ${Math.round(held.ageMs / 1000)}s${held.alive ? '' : ' (holder is GONE - will be reaped)'}` : 'free');
  const client = createClient(cfg, token, { timeoutMs: 3000 });
  const health = token ? await client.tryGet('/api/health') : null;
  line('server', health ? `up  (${health.queued} queued, ${health.scheduled} scheduled)` : 'not reachable');
  if (health) line('push', `${health.push.subscribers} subscriber(s)`);

  // One plain-English fix line per problem, the same checks the setup page
  // shows - so "what do I do now" is answered here too.
  const checks = setup.runChecks({ cfg, paths, health });
  const problems = checks.filter((c) => !c.ok);
  console.log(problems.length ? `\n  To fix (${problems.length})` : '\n  Setup steps: all done');
  for (const c of problems) {
    console.log(`  \u2717  ${c.label}${c.detail ? `  (${c.detail})` : ''}`);
    console.log(`       Fix: ${c.fix}`);
  }

  if (warnings.length || engineHints.length) {
    console.log('\n  Worth knowing');
    for (const w of warnings) console.log(`  ${w.level === 'warn' ? '!' : 'i'}  ${w.msg}`);
    for (const h of engineHints) console.log(`  !  ${h}`);
  }
  console.log('');
}

async function cmdToken(argv) {
  const boot = bootstrap(argv);
  const token = ensureToken(boot.paths, { rotate: !!argv.flags.rotate });
  // A running server read its token once at start, so until it restarts it
  // accepts only the OLD one - the new link 401s and looks like rotation broke.
  if (argv.flags.rotate) console.error('  token rotated - restart halyard, then reopen the new link on every device\n');
  if (argv.flags.qr) {
    const link = setup.pairingUrl(boot.cfg, token, setup.tailscaleState(boot.cfg.port));
    console.log(`\n${qr.toTerminal(qr.encode(link, { ecl: 'M' }))}\n\n  ${link}\n`);
    if (/^http:\/\/127\./.test(link)) console.log('  (This link only works on this computer until a tunnel is set up - see `halyard setup`.)\n');
    return;
  }
  const host = boot.cfg.publicUrl || `http://127.0.0.1:${boot.cfg.port}`;
  console.log(argv.flags.url ? `${host}/?token=${token}` : token);
}

// Creates (or with --revoke, deletes) a token that can only queue a message.
// Printed once; the file is 0600 in a 0700 directory, like a secret.
async function cmdInboundToken(argv) {
  const boot = bootstrap(argv);
  const name = require('../src/threads').slug(argv._[1] || '');
  if (!name) {
    console.error('\n  usage: halyard inbound-token <name> [--revoke]\n');
    process.exitCode = 1;
    return;
  }
  const dir = boot.paths.inbound;
  const file = path.join(dir, `${name}.token`);
  if (argv.flags.revoke) {
    try { fs.unlinkSync(file); console.log(`  inbound token "${name}" revoked`); }
    catch (e) { console.error(`  no inbound token named "${name}"`); process.exitCode = 1; }
    return;
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const t = crypto.randomBytes(24).toString('base64url');
  fs.writeFileSync(file, t, { mode: 0o600 });
  const host = boot.cfg.publicUrl || `http://127.0.0.1:${boot.cfg.port}`;
  console.log(`\n  Inbound token "${name}" - it can queue a message and nothing else.`);
  console.log(`  Messages land in the thread "${name}", marked as background.\n`);
  console.log(`  curl -X POST "${host}/api/inbox" -H "Authorization: Bearer ${t}" \\`);
  console.log(`       -H "content-type: application/json" -d '{"message":"the build on main failed"}'\n`);
}

// Prints the JSON to paste into the agent's hook configuration. Printed rather
// than written, because it goes in a file the agent owns and silently editing
// someone's agent settings is exactly the kind of surprise this project should
// not hand out.
async function cmdHookConfig(argv) {
  const boot = bootstrap(argv);
  const target = argv.flags.target ? path.resolve(String(argv.flags.target)) : setup.claudeSettingsPath();
  if (argv.flags.install) {
    // Merged, never overwritten: every hook that is not Halyard's stays where
    // it was, the old file is backed up first, and the change is shown before
    // it is made.
    const p = setup.previewHooks(target);
    if (!p.ok) { console.error(`\n  ${p.error}\n`); process.exitCode = 1; return; }
    if (!p.changed) { console.log(`\n  ${target} already has Halyard's hooks. Nothing to do.\n`); return; }
    console.log(`\n  Change to ${target}:\n`);
    console.log(p.diff.split('\n').map((l) => `    ${l}`).join('\n'));
    if (!argv.flags.yes && !(await askYesNo('Make this change?'))) {
      console.log('\n  Not changed. Re-run with --yes to skip this question.\n');
      return;
    }
    const r = setup.installHooks(target);
    console.log(`\n  Written.${r.backup ? ` Previous version: ${r.backup}` : ''}\n`);
    return;
  }
  const conf = { hooks: { PreToolUse: setup.hookEntries() } };
  console.log(`\n  Paste into your agent's settings (for Claude Code: ${target}),`);
  console.log('  or let Halyard merge it in with a backup:  halyard hook-config --install\n');
  console.log(JSON.stringify(conf, null, 2));
  console.log(`\n  The matcher and the RELAYED_TOOLS set inside permission-relay.js must agree.`);
  console.log(`  A tool missing from the MATCHER never reaches the hook at all.`);
  console.log(`  A tool missing from RELAYED_TOOLS reaches it and is waved through.`);
  console.log(`\n  The steer hook (nudge-inject.js) needs an agent CLI with a pre-tool hook`);
  console.log(`  at all - today that means Claude Code. Copilot and a plain CLI have no such`);
  console.log(`  mechanism, so "halyard doctor" and the phone both mark those engines as`);
  console.log(`  unable to be steered mid-run, same as they already do for the relay.\n`);
  void boot;
}

// A genuine mid-run question, distinct from the approve/deny relay: for a fork
// where both branches are legitimate and only the person holding the phone
// knows which was meant. Needs no pre-tool hook at all - it is just an HTTP
// round trip a script makes - so unlike the relay and the steer hook, this
// works for every engine, not only ones with a pre-tool hook.
//
// The exit code is the contract, not stdout's mere presence: 0 answered (the
// answer is the whole of stdout), 3 nobody answered in time, 4
// unreachable/rejected, 5 the bridge restarted and no longer holds the question,
// so no answer to it is ever coming.
async function cmdAsk(argv) {
  const boot = bootstrap(argv);
  const { cfg, paths } = boot;
  const question = String(argv._[1] || '').trim();
  if (!question) {
    console.error('\n  usage: halyard ask "<question>" [--options "a|b"] [--wait 240]\n');
    process.exitCode = 1;
    return;
  }
  if (!fs.existsSync(paths.token)) {
    console.error('\n  halyard ask: no token yet - run: halyard setup\n');
    process.exitCode = 4;
    return;
  }
  const token = fs.readFileSync(paths.token, 'utf8').trim();
  // Empty, not the /api/ask route's ['Approve','Deny'] default - that emptiness
  // is exactly what already makes the phone's UI (and the push notification)
  // offer a text box instead of two buttons.
  const options = argv.flags.options
    ? String(argv.flags.options).split('|').map((s) => s.trim()).filter(Boolean).slice(0, 4)
    : [];
  const waitSec = Number(argv.flags.wait) || 240;
  const client = createClient(cfg, token, { timeoutMs: 10000 });
  // The long-poll is held up to 25 s by the bridge, so it needs a longer limit.
  const waitClient = createClient(cfg, token, { timeoutMs: 35000 });

  let id;
  try {
    const res = await client.post('/api/ask', { question, command: '', options, timeoutMs: waitSec * 1000 });
    id = res.id;
  } catch (e) {
    console.error(`\n  halyard ask: could not reach the bridge (${e.message})\n`);
    process.exitCode = 4;
    return;
  }

  // Never process.exit() from here - the same trap documented at the top of
  // hooks/permission-relay.js: fetch handles are still open, and exiting from
  // inside an async function can abort the process before stdout flushes,
  // eating the very answer this command exists to print. Letting main() return
  // and process.exitCode do the work is already this file's own pattern.
  const deadline = Date.now() + waitSec * 1000;
  while (Date.now() < deadline) {
    const asked = Date.now();
    const state = await waitClient.tryGet(`/api/state?id=${encodeURIComponent(id)}&wait=25`);
    // A bridge that ignored `wait` (or failed fast) answers at once; degrade to
    // the old 3 s poll rather than spin.
    if (Date.now() - asked < 1000 && (!state || state.status === 'pending')) {
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
    if (!state) continue;
    if (state.status === 'gone') {
      console.error('\n  halyard ask: the bridge restarted before the question was answered\n');
      process.exitCode = 5;
      return;
    }
    if (state.status === 'answered') {
      process.stdout.write(String(state.answer || ''));
      return;
    }
  }
  console.error(`\n  halyard ask: no answer within ${waitSec}s\n`);
  process.exitCode = 3;
}

// Writes the unit for this OS into the data dir and, with register, loads it.
function writeServiceUnit(boot) {
  const { dataDir } = boot;
  const node = process.execPath;
  const entry = path.join(__dirname, 'halyard.js');
  const tmpl = path.join(__dirname, '..', 'scripts', 'service');
  const subs = { NODE: node, ENTRY: entry, DATA_DIR: dataDir, WORKDIR: boot.cfg.workspace, USER: os.userInfo().username };
  const fill = (s) => s.replace(/\{\{(\w+)\}\}/g, (_, k) => subs[k] || '');
  const which = process.platform === 'win32' ? 'windows.ps1'
    : process.platform === 'darwin' ? 'launchd.plist' : 'systemd.service';
  const outName = process.platform === 'win32' ? 'halyard-install-task.ps1'
    : process.platform === 'darwin' ? 'com.halyard.bridge.plist' : 'halyard.service';
  const out = path.join(dataDir, outName);
  fs.writeFileSync(out, fill(fs.readFileSync(path.join(tmpl, which), 'utf8')));
  return out;
}

async function installService(boot, { register = false } = {}) {
  const out = writeServiceUnit(boot);
  if (!register) return { ok: true, out, registered: false };
  return { ...setup.registerService(process.platform, out), out, registered: true };
}

async function cmdInstallService(argv) {
  const boot = bootstrap(argv);
  // --register is the setup page's "Yes, start on login": the same unit,
  // loaded for this user only. Without it the unit is written and the
  // commands are printed, never run.
  if (argv.flags.register) {
    const r = await installService(boot, { register: true });
    console.log(r.ok ? `\n  Halyard will start on login (${r.out}).\n  To undo: ${r.undo}\n` : `\n  ${r.error}\n`);
    if (!r.ok) process.exitCode = 1;
    return;
  }
  const { out } = await installService(boot);
  console.log(`\n  Wrote ${out}\n`);
  const plan = setup.registerCommands(process.platform, out);
  console.log('  Register it (or re-run with --register to have Halyard do it):');
  if (plan.copyTo) console.log(`    mkdir -p "${path.dirname(plan.copyTo)}" && cp "${out}" "${plan.copyTo}"`);
  for (const [cmd, args] of plan.cmds) console.log(`    ${cmd} ${args.map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(' ')}`);
  console.log(`  Undo: ${plan.undo}\n`);
}

// Syntax gate for the page's inline script, so a broken UI cannot be committed.
// The page is served fresh on every request and never bundled, which is what
// makes edits apply instantly - and also what means nothing else would catch a
// syntax error in it before a phone did.
async function cmdCheckPage() {
  const file = path.join(__dirname, '..', 'public', 'index.html');
  const html = fs.readFileSync(file, 'utf8');
  const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  if (!scripts.length) throw new Error('no inline script found in index.html - did the page change shape?');
  for (const [i, src] of scripts.entries()) {
    try {
      new (require('vm').Script)(src, { filename: `index.html#script${i}` });
    } catch (e) {
      throw new Error(`index.html inline script ${i}: ${e.message}`);
    }
  }
  console.log(`index.html: ${scripts.length} inline script(s) parse cleanly`);
}

function usage() {
  console.log(`
  halyard ${pkg.version} - drive a coding agent from your phone

    halyard setup                 guided setup in your browser, with a tick per step
      [--no-browser]               the same steps in this terminal
    halyard start                 server + watcher (the normal command)
    halyard serve                 server only
    halyard watch                 one watcher pass (for cron / systemd timer)
    halyard doctor                what is configured, reachable and risky
    halyard token [--url|--qr]    print the token, the full link, or a QR code to scan
    halyard inbound-token <name>  a token that can only queue a message [--revoke]
    halyard ask "<question>"      block and ask the phone a genuine question
      [--options "a|b"] [--wait 240]   (for the agent to run mid-turn, not you)
    halyard hook-config           agent hook config for the approve/deny relay
      [--install [--yes]]          and the steer hook; --install merges it into
                                   your Claude settings, with a backup
    halyard install-service       write a service unit for this OS
      [--register]                 and turn it on, so Halyard starts on login

  Common flags
    --data-dir <path>   where state lives (default: OS data dir)
    --port <n>          default 4545
    --host <addr>       default 127.0.0.1 - see docs/REMOTE-ACCESS.md
    --workspace <path>  the directory the agent may work in
    --engine <name>     claude | copilot | <your own>
    --no-relay          disable the approve/deny backstop (read SECURITY.md)
`);
}

async function main() {
  const argv = parseArgv(process.argv.slice(2));
  const cmd = argv._[0] || 'help';
  const table = {
    setup: cmdSetup,
    start: cmdStart,
    serve: (a) => cmdStart(a, { withWatcher: false }),
    watch: cmdWatch,
    doctor: cmdDoctor,
    token: cmdToken,
    'inbound-token': cmdInboundToken,
    ask: cmdAsk,
    'hook-config': cmdHookConfig,
    'install-service': cmdInstallService,
    'check-page': cmdCheckPage,
  };
  if (cmd === 'help' || cmd === '--help' || cmd === '-h' || !table[cmd]) {
    usage();
    process.exitCode = table[cmd] ? 0 : (cmd === 'help' || cmd.startsWith('-') ? 0 : 1);
    if (!table[cmd] && cmd !== 'help' && !cmd.startsWith('-')) console.error(`  unknown command: ${cmd}\n`);
    return;
  }
  await table[cmd](argv);
}

if (require.main === module) {
  main().catch((e) => {
    console.error(`\n  halyard: ${e.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { parseArgv, whichSync, cliOverrides, cmdAsk, RELAY_MATCHER, writeServiceUnit };
