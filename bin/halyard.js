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
const watcher = require('../src/watcher');
const pushmod = require('../src/push');
const lockmod = require('../src/lock');

const pkg = require('../package.json');

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
  try { fs.writeFileSync(paths.pushSubs, JSON.stringify(subs)); } catch (e) { /* best effort */ }
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

  console.log(`\n  Halyard ${pkg.version} is set up.\n`);
  console.log(`  data dir   ${dataDir}`);
  console.log(`  config     ${paths.config}`);
  console.log(`  workspace  ${cfg.workspace}`);
  console.log(`  engine     ${cfg.defaultEngine} (${cfg.engines[cfg.defaultEngine].command || 'not set'})`);
  console.log(`\n  Start it:  halyard start`);
  console.log(`  Open:      http://127.0.0.1:${cfg.port}/?token=${token}\n`);
  console.log(`  Then read: halyard doctor      (checks, and what is risky)`);
  console.log(`             halyard hook-config (wire up the approve/deny relay)\n`);
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
      subs = subs.filter((s) => s.endpoint !== sub.endpoint).concat(sub);
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
  for (const e of Object.values(cfg.engines)) {
    const found = e.command ? whichSync(e.command) : null;
    const mark = e.name === cfg.defaultEngine ? '*' : ' ';
    console.log(`  ${mark} ${e.name.padEnd(10)} ${found ? found : (e.command ? `${e.command}  NOT ON PATH` : 'no command configured')}${e.supportsRelayHook ? '' : '   [no pre-tool hook: relay cannot arm]'}`);
  }

  console.log('\n  Runtime');
  const held = lockmod.inspect(paths.lockDir, 'watch');
  line('run lock', held ? `held by pid ${held.pid} for ${Math.round(held.ageMs / 1000)}s${held.alive ? '' : ' (holder is GONE - will be reaped)'}` : 'free');
  const client = createClient(cfg, token, { timeoutMs: 3000 });
  const health = token ? await client.tryGet('/api/health') : null;
  line('server', health ? `up  (${health.queued} queued, ${health.scheduled} scheduled)` : 'not reachable');
  if (health) line('push', `${health.push.subscribers} subscriber(s)`);

  if (warnings.length) {
    console.log('\n  Worth knowing');
    for (const w of warnings) console.log(`  ${w.level === 'warn' ? '!' : 'i'}  ${w.msg}`);
  }
  console.log('');
}

// A `which` that does not shell out, so it behaves the same everywhere and
// cannot be tricked by a shell alias.
function whichSync(cmd) {
  if (cmd.includes(path.sep) || cmd.includes('/')) return fs.existsSync(cmd) ? cmd : null;
  const exts = process.platform === 'win32'
    ? (process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';')
    : [''];
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const full = path.join(dir, cmd + ext);
      try {
        if (fs.statSync(full).isFile()) return full;
      } catch (e) { /* next */ }
    }
  }
  return null;
}

async function cmdToken(argv) {
  const boot = bootstrap(argv);
  const token = ensureToken(boot.paths, { rotate: !!argv.flags.rotate });
  if (argv.flags.rotate) console.error('  token rotated - every device must reopen the new link\n');
  const host = boot.cfg.publicUrl || `http://127.0.0.1:${boot.cfg.port}`;
  console.log(argv.flags.url ? `${host}/?token=${token}` : token);
}

// Prints the JSON to paste into the agent's hook configuration. Printed rather
// than written, because it goes in a file the agent owns and silently editing
// someone's agent settings is exactly the kind of surprise this project should
// not hand out.
async function cmdHookConfig(argv) {
  const boot = bootstrap(argv);
  const hook = path.join(__dirname, '..', 'hooks', 'permission-relay.js');
  const conf = {
    hooks: {
      PreToolUse: [{
        // MUST name every tool that can run a shell, not just Bash. A CLI that
        // also ships a PowerShell tool lets a run walk around a Bash-only
        // matcher entirely, and under a loosened permission mode "unrelayed"
        // means "runs, unprompted".
        matcher: 'Bash|PowerShell',
        hooks: [{ type: 'command', command: `node "${hook}"` }],
      }],
    },
  };
  console.log(`\n  Paste into your agent's settings (for Claude Code: .claude/settings.json in ${boot.cfg.workspace}):\n`);
  console.log(JSON.stringify(conf, null, 2));
  console.log(`\n  The matcher and the RELAYED_TOOLS set inside the hook must agree.`);
  console.log(`  A tool missing from the MATCHER never reaches the hook at all.`);
  console.log(`  A tool missing from RELAYED_TOOLS reaches it and is waved through.\n`);
}

async function cmdInstallService(argv) {
  const boot = bootstrap(argv);
  const { dataDir } = boot;
  const node = process.execPath;
  const entry = path.join(__dirname, 'halyard.js');
  const tmpl = path.join(__dirname, '..', 'scripts', 'service');

  const subs = { NODE: node, ENTRY: entry, DATA_DIR: dataDir, WORKDIR: boot.cfg.workspace, USER: os.userInfo().username };
  const fill = (s) => s.replace(/\{\{(\w+)\}\}/g, (_, k) => subs[k] || '');

  const which = process.platform === 'win32' ? 'windows.ps1'
    : process.platform === 'darwin' ? 'launchd.plist' : 'systemd.service';
  const text = fill(fs.readFileSync(path.join(tmpl, which), 'utf8'));
  const outName = process.platform === 'win32' ? 'halyard-install-task.ps1'
    : process.platform === 'darwin' ? 'com.halyard.bridge.plist' : 'halyard.service';
  const out = path.join(dataDir, outName);
  fs.writeFileSync(out, text);

  console.log(`\n  Wrote ${out}\n`);
  // Printed, never executed. Registering a background service is a system-wide,
  // hard-to-reverse change, and it needs the user's own hands and their own
  // idea of which init system they are actually using.
  if (process.platform === 'win32') {
    console.log('  Register it (an elevated shell is NOT required for a user task):');
    console.log(`    powershell -ExecutionPolicy Bypass -File "${out}"\n`);
  } else if (process.platform === 'darwin') {
    console.log('  Register it:');
    console.log(`    cp "${out}" ~/Library/LaunchAgents/`);
    console.log('    launchctl load ~/Library/LaunchAgents/com.halyard.bridge.plist\n');
  } else {
    console.log('  Register it:');
    console.log(`    mkdir -p ~/.config/systemd/user && cp "${out}" ~/.config/systemd/user/`);
    console.log('    systemctl --user daemon-reload && systemctl --user enable --now halyard\n');
  }
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

    halyard setup                 create config, token and push keys
    halyard start                 server + watcher (the normal command)
    halyard serve                 server only
    halyard watch                 one watcher pass (for cron / systemd timer)
    halyard doctor                what is configured, reachable and risky
    halyard token [--url]         print the token, or the full link
    halyard hook-config           agent hook config for the approve/deny relay
    halyard install-service       write a service unit for this OS

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

module.exports = { parseArgv, whichSync, cliOverrides };
