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
      '--model', '{{model}}',
      '--resume', '{{session}}',
    ],
    stream: 'claude-json',
    modelMap: {
      opus: 'claude-opus-5',
      sonnet: 'claude-sonnet-5',
      haiku: 'claude-haiku-4-5-20251001',
    },
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

  // --- safety --------------------------------------------------------------
  relay: {
    // Approve/deny on the phone for mutating git, recursive deletes and
    // outbound data. On by default: the whole point of running an agent
    // unattended is that nobody is watching it.
    enabled: true,
    timeoutMs: 5 * 60 * 1000,
    // Which rule families to relay. Trim if a category is pure noise for you.
    rules: ['git', 'destructive-fs', 'network-egress'],
  },

  // --- delivery ------------------------------------------------------------
  push: { enabled: true, subject: 'mailto:you@example.com' },
  ntfy: { enabled: false, topic: '' },

  // --- limits --------------------------------------------------------------
  maxUploadBytes: 25 * 1024 * 1024,
  notificationRing: 30,
  transcriptRing: 200,
  archiveMaxBytes: 4 * 1024 * 1024,

  // --- misc ----------------------------------------------------------------
  // Poll interval for the built-in watcher loop. The server also nudges the
  // watcher the instant a message is queued, so this is only the safety net
  // for a message queued while the loop was busy.
  watchIntervalMs: 60 * 1000,
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
  const engines = {};
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
  return cfg;
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
  const home = os.homedir();
  if (cfg.workspace === home || home.startsWith(cfg.workspace + path.sep)) {
    out.push({
      level: 'warn',
      msg: `Workspace is ${cfg.workspace}, which contains your whole home directory. Narrow it unless you mean it.`,
    });
  }
  const engine = cfg.engines[cfg.defaultEngine];
  if (engine && !engine.supportsRelayHook && cfg.relay && cfg.relay.enabled) {
    out.push({
      level: 'warn',
      msg: `Engine "${cfg.defaultEngine}" exposes no pre-tool hook, so the relay cannot arm for it. Its runs are unsupervised even though the relay is switched on.`,
    });
  }
  if (cfg.push && cfg.push.enabled && /you@example\.com/.test(cfg.push.subject || '')) {
    out.push({ level: 'info', msg: 'push.subject is still the example address. Push services want a real mailto: or https: contact.' });
  }
  return out;
}

module.exports = { DEFAULTS, BUILTIN_ENGINES, ENV_MAP, load, audit, deepMerge, setPath };
