// PreToolUse hook: delivers a short instruction the phone parked on a run in
// flight, at the run's next tool-call boundary.
//
// Wire it up with matcher `*` (see `halyard hook-config`) - unlike the
// approve/deny relay, this one has to see EVERY tool call, not just the
// shell-running ones, because a run that only edits files makes no Bash call
// and would otherwise never receive its nudge.
//
// Delivery is a `permissionDecision: "deny"` whose reason carries the text.
// That is not a workaround for want of a nicer channel: it is the one
// mechanism in the PreToolUse contract whose text is guaranteed to reach the
// MODEL rather than just the user, and permission-relay.js already depends on
// exactly that path working. The model sees a denied call plus a reason that
// says the call is worth repeating - not a genuine refusal.
//
// This only works for an engine whose CLI exposes a pre-tool hook at all
// (`engine.supportsRelayHook` - the flag is named for the relay but the
// underlying capability is the same one this file needs). Claude Code today;
// nothing else.

const fs = require('fs');
const os = require('os');
const path = require('path');

const relay = require('./permission-relay');

function dataDir() {
  if (process.env.HALYARD_DATA_DIR) return path.resolve(process.env.HALYARD_DATA_DIR);
  const home = os.homedir();
  if (process.platform === 'win32') return path.join(process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'halyard');
  if (process.platform === 'darwin') return path.join(home, 'Library', 'Application Support', 'halyard');
  if (process.env.XDG_STATE_HOME) return path.join(process.env.XDG_STATE_HOME, 'halyard');
  return path.join(home, '.local', 'state', 'halyard');
}

const PORT = Number(process.env.HALYARD_PORT) || 4545;
const BASE = `http://127.0.0.1:${PORT}`;
const TOKEN_FILE = path.join(dataDir(), 'token.txt');

function passthrough() {
  process.exitCode = 0;
}

// Never process.exit() here, for the same reason as permission-relay.js: this
// only runs from inside the async main() with undici's fetch handles still
// open, and exiting there can abort the process before stdout flushes.
function deny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  }));
  process.exitCode = 0;
}

async function main() {
  const raw = fs.readFileSync(0, 'utf8');
  let input;
  try {
    input = JSON.parse(raw);
  } catch (e) {
    return passthrough();
  }

  // Never steal a call the relay is about to handle. Denying it here would
  // throw away an approval that was just tapped, and the run would re-ask for
  // the identical git command a moment later - which reads as the relay
  // malfunctioning, not as a second, unrelated feature.
  const command = (input.tool_input && input.tool_input.command) || '';
  if (relay.matchRelayRule(input.tool_name, command)) return passthrough();

  let token;
  try {
    token = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
  } catch (e) {
    return passthrough();
  }

  try {
    const res = await fetch(`${BASE}/api/run/nudge?consume=1&token=${token}`, {
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return passthrough();
    const body = await res.json();
    if (body && body.text) return deny(`A message arrived from the phone mid-run: "${body.text}" - factor it into what you do next, then continue. This is not a real permission refusal.`);
    return passthrough();
  } catch (e) {
    // Every failure here is a passthrough: bridge down, slow, no token, bad
    // JSON. Missing a nudge costs one undelivered aside; failing closed would
    // leave every tool call in the run denied.
    return passthrough();
  }
}

if (require.main === module) {
  main().catch(() => passthrough());
}

module.exports = { dataDir };
