// Configuration. Everything a user could reasonably want to change lives here
// as data, not as an edit to a source file - that is the difference between a
// project other people can run and a project that runs on one machine.
//
// Layering, later overrides earlier:
//   defaults  ->  config file  ->  HALYARD_* env vars  ->  CLI flags
//
// Engines in particular are DATA. Adding support for a new agent CLI should not
// require a code change: declare its binary, its argument shape and which
// stream dialect it speaks, and the watcher can drive it.

const fs = require('fs');
const os = require('os');
const path = require('path');

// ---------------------------------------------------------------------------
// Built-in engine definitions.
//
// `args` is a template list. Placeholders are substituted at spawn time:
//   {{workspace}}        the directory the agent may touch
//   {{model}}            resolved through the engine's modelMap
//   {{session}}          prior session id, for resuming a thread
//   {{permissionMode}}   the configured permission mode
//
// Any argument PAIR whose value resolves to empty is dropped whole - that is
// what lets one template cover "first message in a thread" (no --resume) and
// "default model" (no --model) without three near-identical templates.
//
// The prompt is NEVER in this list. It goes in on stdin - see watcher.js for
// the full reason, but in short: quoting a multi-paragraph prompt through a
// native-argument boundary silently truncates it on at least one major
// platform, and a truncated prompt produces a plausible-looking wrong answer
// rather than an error.
const BUILTIN_ENGINES = {
  claude: {
    label: 'Claude Code',
    command: 'claude',
    args: [
      '--print',
      '--output-format', 'stream-json',
      '--verbose',
      '--permission-mode', '{{permissionMode}}',
      '--add-dir', '{{workspace}}',
      '--add-dir', '{{secrets}}',
      '--model', '{{model}}',
      '--resume', '{{session}}',
    ],
    stream: 'claude-json',
    modelMap: {
      opus: 'claude-opus-5',
      sonnet: 'claude-sonnet-5',
      haiku: 'claude-haiku-4-5-20251001',
    },
    // The phone's "Auto" model: resolved per message to `light` or `heavy` (both
    // modelMap keys) by src/router.js. A light start may hand the turn up by
    // replying with only "ESCALATE: <reason>", and the heavy model retakes it on
    // the same session. Set to null in an engine override to hide Auto for it.
    auto: { light: 'sonnet', heavy: 'opus' },
    // Claude Code fails the whole run with this on stderr when a session id no
    // longer resolves. Detected so the watcher can drop the id and retake the
    // turn fresh, rather than reporting a failure the phone cannot act on.
    staleSessionError: 'No conversation found with session ID',
    supportsRelayHook: true,
  },
  copilot: {
    label: 'GitHub Copilot CLI',
    command: 'copilot',
    args: [
      '--allow-all-tools',
      '--add-dir', '{{workspace}}',
      '--add-dir', '{{secrets}}',
      '--output-format', 'json',
      '--model', '{{model}}',
      '--resume', '{{session}}',
    ],
    stream: 'copilot-json',
    modelMap: {},
    // No documented pre-tool hook mechanism, so the approve/deny relay cannot
    // arm for it. Surfaced in the UI and in `halyard doctor` rather than left
    // as a footnote in a design document nobody reads.
    supportsRelayHook: false,
  },
  // A deliberately dumb fallback: any CLI that takes a prompt on stdin and
  // prints an answer on stdout. No activity line, no session resume, no cost
  // reporting - but it works, and it is the template for adding your own.
  plain: {
    label: 'Plain stdin/stdout CLI',
    command: '',
    args: [],
    stream: 'text',
    modelMap: {},
    supportsRelayHook: false,
  },
};

const DEFAULTS = {
  // --- network -------------------------------------------------------------
  // Loopback by default, always. Remote access is meant to come from a tunnel
  // that terminates TLS and authenticates the device (Tailscale Serve,
  // cloudflared, an SSH forward) - see docs/REMOTE-ACCESS.md. Binding 0.0.0.0
  // is possible but it is an explicit, documented, warned-about choice.
  host: '127.0.0.1',
  port: 4545,
  publicUrl: '',

  // --- agent ---------------------------------------------------------------
  defaultEngine: 'claude',
  engines: {},

  // The directory the agent is allowed to work in. Defaults to the CWD at setup
  // time, NOT the home directory: an agent running unattended with write access
  // to an entire user profile is a decision someone should make on purpose.
  workspace: '',
  // Threads that run somewhere other than `workspace`. Keys are thread names
  // (the slug form), values are directories. Set here and nowhere else: this
  // is the boundary of what the agent may touch, so the phone cannot change it.
  threadWorkspaces: {},

  // Passed straight through to the engine. 'default' means the agent's own
  // permission rules apply. Anything looser is opt-in and `doctor` says so.
  permissionMode: 'default',

  // Wall-clock budget for one run. A run that hangs holds the lock, and a held
  // lock is indistinguishable from a dead bridge from the phone's side.
  runTimeoutMs: 30 * 60 * 1000,
  // How long to keep reading a pipe after the child has exited. A grandchild
  // that inherited stdout (a lingering shell from a tool call) can hold it open
  // forever; without this bound the run never ends. See watcher.js.
  postExitTimeoutMs: 20 * 1000,

  // --- failover --------------------------------------------------------------
  // Off by default: a silent reroute to a second engine changes which model
  // answered your message, and that should be opt-in. `to` names a configured
  // engine; enabling this with no `to`, or a `to` that names nothing real, is
  // caught by `audit()` below rather than failing a run at 2am.
  failover: { enabled: false, to: '' },

  // --- safety --------------------------------------------------------------
  relay: {
    // Approve/deny on the phone for mutating git, recursive deletes and
    // outbound data. On by default: the whole point of running an agent
    // unattended is that nobody is watching it.
    enabled: true,
    timeoutMs: 5 * 60 * 1000,
    // Which rule families to relay. Trim if a category is pure noise for you.
    // secret-egress: one command that reads a secret and talks to the network.
    // tainted-egress: any off-machine request once the run has read untrusted
    // content (the web, an MCP tool, an upload or a download).
    rules: ['git', 'destructive-fs', 'network-egress', 'secret-egress', 'tainted-egress'],
    // `gh pr merge` on a repo GitHub reports as PRIVATE passes with no tap. Off
    // by default: turn it on only if merging into your own private repos is
    // something you would approve without reading anyway.
    privateMergeWithoutTap: false,
    // Rule families the phone may approve "for the rest of this run". Only git
    // by default: a push is recoverable; a recursive delete or an upload after
    // reading untrusted content is not something to wave through in bulk.
    runScopedRules: ['git'],
  },

  // --- usage guard ---------------------------------------------------------
  // Before a message is popped, Claude Code's own subscription usage gauges
  // (the numbers its /usage screen shows) are checked; if any window is at or
  // above maxPercent the message stays queued and the phone is told, at most
  // once per announceEveryMs. Fails OPEN: no credentials, an error or no gauges
  // all let the run go ahead. 0 disables it. Only engines that speak
  // claude-json are guarded - the gauges are Anthropic's.
  usageGuard: { maxPercent: 0, announceEveryMs: 30 * 60 * 1000 },

  // --- spend guard -----------------------------------------------------------
  // Before a message is popped, today's recorded cost (local day) is checked;
  // at or above dailyUsd the message stays queued and the phone is told, at
  // most once per announceEveryMs. 0 disables it. Only runs that report a cost
  // are counted, so an engine that reports none is never held by this.
  spendGuard: { dailyUsd: 0, announceEveryMs: 30 * 60 * 1000 },

  // --- watchdog --------------------------------------------------------------
  // A message that has been due for this long with no run in flight and no
  // guard holding it means the watcher is not running. The phone gets one
  // notice per stuck message. 0 disables it.
  watchdog: { staleMs: 10 * 60 * 1000 },

  // --- diff ------------------------------------------------------------------
  // After a run that edited files in a git workspace, the changes since the
  // run started are written to artifacts/ as a page and linked from the reply.
  // Read-only git, bounded in time and size. Off = no git is ever spawned.
  diff: { enabled: true, maxBytes: 512 * 1024, timeoutMs: 10 * 1000 },

  // --- long threads ----------------------------------------------------------
  // A resumed thread resends its whole history every turn, so it gets more
  // expensive per message the longer nobody clears it. After a run whose
  // context ended at or above shrinkAtTokens, the transcript's bulky tool
  // output is pruned into a new session (if that saves shrinkMinPercent); at or
  // above clearAtTokens the session is dropped and the next message starts
  // fresh from the handover. 0 disables either.
  context: { shrinkAtTokens: 90000, shrinkMinPercent: 15, clearAtTokens: 150000 },

  // --- background runs -------------------------------------------------------
  // A cheaper model for procedural runs nobody is waiting on: messages queued
  // with `background: true`, repeats (when `repeats` is on), and any thread
  // named in `threads`. Applies only when the message picked no model itself.
  // '' disables it.
  background: { model: '', threads: [], repeats: false },

  // --- delivery ------------------------------------------------------------
  push: { enabled: true, subject: 'mailto:you@example.com' },
  ntfy: { enabled: false, topic: '' },

  // --- limits --------------------------------------------------------------
  maxUploadBytes: 25 * 1024 * 1024,
  notificationRing: 30,
  transcriptRing: 200,
  archiveMaxBytes: 4 * 1024 * 1024,
  // How many rotated archive files a search or a spend rollup reads, newest
  // first, on top of the live one. Older files stay on disk and are still
  // covered by a delete; they are just not searched.
  archiveSearchFiles: 12,

  // --- misc ----------------------------------------------------------------
  // Poll interval for the built-in watcher loop. The server also nudges the
  // watcher the instant a message is queued, so this is only the safety net
  // for a message queued while the loop was busy.
  watchIntervalMs: 60 * 1000,
  // How often the change stream sends a ping. The page counts any stream
  // message as contact with the bridge, so this is also how quickly a dead
  // connection is noticed (two missed pings).
  ssePingMs: 25 * 1000,
  logLevel: 'info',
};

// Env overrides. Kept as an explicit table rather than a generic
// HALYARD_FOO_BAR -> foo.bar transform, because a typo in a generic scheme is
// silently ignored and a typo in this one is visible in `halyard doctor`.
const ENV_MAP = {
  HALYARD_HOST: ['host', String],
  HALYARD_PORT: ['port', Number],
  HALYARD_PUBLIC_URL: ['publicUrl', String],
  HALYARD_ENGINE: ['defaultEngine', String],
  HALYARD_WORKSPACE: ['workspace', String],
  HALYARD_PERMISSION_MODE: ['permissionMode', String],
  HALYARD_RELAY: ['relay.enabled', (v) => v !== '0' && v !== 'false'],
  HALYARD_NTFY_TOPIC: ['ntfy.topic', String],
  HALYARD_LOG_LEVEL: ['logLevel', String],
  HALYARD_USAGE_MAX_PERCENT: ['usageGuard.maxPercent', Number],
  HALYARD_SPEND_DAILY_USD: ['spendGuard.dailyUsd', Number],
  HALYARD_BACKGROUND_MODEL: ['background.model', String],
};

function isPlainObject(v) {
  return v && typeof v === 'object' && !Array.isArray(v);
}

function deepMerge(base, over) {
  const out = Array.isArray(base) ? base.slice() : { ...base };
  for (const [k, v] of Object.entries(over || {})) {
    out[k] = isPlainObject(v) && isPlainObject(base && base[k]) ? deepMerge(base[k], v) : v;
  }
  return out;
}

function setPath(obj, dotted, value) {
  const parts = dotted.split('.');
  let cur = obj;
  while (parts.length > 1) {
    const k = parts.shift();
    if (!isPlainObject(cur[k])) cur[k] = {};
    cur = cur[k];
  }
  cur[parts[0]] = value;
}

// A corrupt config is reported and skipped, never fatal. An unreachable bridge
// is worse than a bridge running on defaults, and the phone is often the only
// device around to notice either way.
function readFileConfig(file, warn) {
  try {
    if (!file || !fs.existsSync(file)) return {};
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return isPlainObject(parsed) ? parsed : {};
  } catch (e) {
    warn(`config file ${file} is not valid JSON (${e.message}); using defaults`);
    return {};
  }
}

function load(opts) {
  const { file, env = process.env, cli = {}, warn = () => {} } = opts || {};
  let cfg = deepMerge(DEFAULTS, {});
  cfg = deepMerge(cfg, readFileConfig(file, warn));

  for (const [envKey, [dotted, coerce]] of Object.entries(ENV_MAP)) {
    if (env[envKey] === undefined || env[envKey] === '') continue;
    setPath(cfg, dotted, coerce(env[envKey]));
  }
  cfg = deepMerge(cfg, cli);

  // Engines: built-ins are the base, user entries merge on top, so overriding
  // just `command` (a binary that is not on PATH) does not mean restating the
  // whole argument template.
  //
  // No prototype: every "is this a configured engine?" check is a plain
  // `cfg.engines[name]` lookup on a name the phone supplies, and on an ordinary
  // object `constructor` or `toString` passes it - queueing a message for an
  // "engine" with no command, which then fails the run.
  const engines = Object.create(null);
  for (const [name, def] of Object.entries(BUILTIN_ENGINES)) engines[name] = { ...def, name };
  for (const [name, def] of Object.entries(cfg.engines || {})) {
    const base = engines[name] || { name, label: name, stream: 'text', args: [], modelMap: {}, supportsRelayHook: false };
    engines[name] = { ...base, ...def, name };
  }
  cfg.engines = engines;

  if (!cfg.workspace) cfg.workspace = process.cwd();
  cfg.workspace = path.resolve(String(cfg.workspace).replace(/^~(?=$|[/\\])/, os.homedir()));

  if (!cfg.engines[cfg.defaultEngine]) {
    warn(`defaultEngine "${cfg.defaultEngine}" is not defined; falling back to claude`);
    cfg.defaultEngine = 'claude';
  }
  cfg.port = Number(cfg.port) || DEFAULTS.port;
  // Read with .filter and .includes. A string there would throw in audit() at
  // startup, or worse, turn .includes into a substring match.
  if (cfg.relay && !Array.isArray(cfg.relay.runScopedRules)) {
    cfg.relay.runScopedRules = typeof cfg.relay.runScopedRules === 'string' ? [cfg.relay.runScopedRules] : [];
  }
  return cfg;
}

// Whether `inner` is `outer` or sits somewhere under it. Not a startsWith on
// `outer + sep`: a root already ends in its separator (`C:\`, `/`), so that
// test built `C:\\` and `//` and missed the two widest workspaces there are.
// Case-insensitive on Windows, where `c:\users\me` and `C:\Users\me` are one
// directory.
function containsPath(outer, inner, platform = process.platform) {
  const p = platform === 'win32' ? path.win32 : path.posix;
  const norm = (s) => (platform === 'win32' ? p.resolve(s).toLowerCase() : p.resolve(s));
  const rel = p.relative(norm(outer), norm(inner));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${p.sep}`) && !p.isAbsolute(rel));
}

// The directory a thread's runs happen in. An unlisted thread, or a listed one
// whose value is not a string, uses the default workspace. hasOwnProperty, not
// map[name]: the name comes from a request, and `constructor` exists on every
// plain object.
function workspaceFor(cfg, threadName) {
  const map = cfg.threadWorkspaces || {};
  const raw = Object.prototype.hasOwnProperty.call(map, threadName) ? map[threadName] : null;
  if (typeof raw !== 'string' || !raw.trim()) return cfg.workspace;
  return path.resolve(raw.replace(/^~(?=$|[/\\])/, os.homedir()));
}

// Non-fatal advisories, surfaced by `halyard doctor` and on the phone's status
// panel. Each one is a real, specific exposure - not a lint rule. They are
// warnings rather than errors on purpose: every one of them is a legitimate
// choice for somebody, and a tool that refuses to run in a configuration its
// author disagrees with just gets forked.
function audit(cfg) {
  const out = [];
  if (!['127.0.0.1', '::1', 'localhost'].includes(cfg.host)) {
    out.push({
      level: 'warn',
      msg: `Bound to ${cfg.host}, not loopback. Anything that can reach this port can reach your agent, and the bearer token is the only gate.`,
    });
  }
  if (cfg.permissionMode !== 'default') {
    out.push({
      level: 'warn',
      msg: `permissionMode is "${cfg.permissionMode}". Tool calls will not prompt locally, so the approve/deny relay is your only backstop.`,
    });
  }
  if (!cfg.relay || !cfg.relay.enabled) {
    out.push({
      level: 'warn',
      msg: 'Approve/deny relay is disabled. Unattended runs can commit, push, delete recursively and upload with no confirmation.',
    });
  }
  if (containsPath(cfg.workspace, os.homedir())) {
    out.push({
      level: 'warn',
      msg: `Workspace is ${cfg.workspace}, which contains your whole home directory. Narrow it unless you mean it.`,
    });
  }
  const risky = ((cfg.relay && cfg.relay.runScopedRules) || []).filter((r) => r !== 'git');
  if (risky.length) {
    out.push({
      level: 'warn',
      msg: `relay.runScopedRules includes ${risky.join(', ')}. One tap can then approve every such command for the rest of a run, including ones you never see.`,
    });
  }
  for (const [name, raw] of Object.entries(cfg.threadWorkspaces || {})) {
    const dir = workspaceFor(cfg, name);
    if (typeof raw !== 'string' || dir === cfg.workspace) continue;
    if (!fs.existsSync(dir)) {
      out.push({ level: 'warn', msg: `Thread "${name}" is mapped to ${dir}, which does not exist. Its runs will fail to start.` });
    }
    if (containsPath(dir, os.homedir())) {
      out.push({ level: 'warn', msg: `Thread "${name}" runs in ${dir}, which contains your whole home directory.` });
    }
  }
  const engine = cfg.engines[cfg.defaultEngine];
  if (engine && !engine.supportsRelayHook && cfg.relay && cfg.relay.enabled) {
    out.push({
      level: 'warn',
      msg: `Engine "${cfg.defaultEngine}" exposes no pre-tool hook, so the relay cannot arm for it. Its runs are unsupervised even though the relay is switched on.`,
    });
  }
  if (cfg.failover && cfg.failover.enabled && !cfg.engines[cfg.failover.to]) {
    out.push({
      level: 'warn',
      msg: `failover.to "${cfg.failover.to}" is not a configured engine, so failover.enabled has no effect.`,
    });
  }
  if (cfg.push && cfg.push.enabled && /you@example\.com/.test(cfg.push.subject || '')) {
    out.push({ level: 'info', msg: 'push.subject is still the example address. Push services want a real mailto: or https: contact.' });
  }
  return out;
}

module.exports = { DEFAULTS, BUILTIN_ENGINES, ENV_MAP, load, audit, workspaceFor, deepMerge, setPath, containsPath };
