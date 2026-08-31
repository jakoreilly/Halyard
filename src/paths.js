// Where Halyard keeps its runtime state.
//
// The single most important difference from a "just run it in the repo folder"
// design: state does NOT live next to the code. A clone you `git pull` is not a
// place to keep a bearer token, a push keypair and a message archive - one
// stray `git clean -xdf` and the install is gone, and a contributor who forks
// the repo inherits paths that only make sense on the original machine.
//
// Resolution order, first hit wins:
//   1. --data-dir <path>            (explicit, per-invocation)
//   2. HALYARD_DATA_DIR             (explicit, per-environment)
//   3. $XDG_STATE_HOME/halyard      (Linux, if XDG_STATE_HOME is set)
//   4. %LOCALAPPDATA%\halyard       (Windows)
//      ~/Library/Application Support/halyard  (macOS)
//      ~/.local/state/halyard       (Linux fallback)
//
// A relative --data-dir of "." gives the old portable behaviour for anyone who
// wants everything in one folder (a USB stick, a container volume).

const os = require('os');
const path = require('path');
const fs = require('fs');

function defaultDataDir(env = process.env, platform = process.platform) {
  if (env.HALYARD_DATA_DIR) return path.resolve(env.HALYARD_DATA_DIR);
  const home = os.homedir();
  if (platform === 'win32') {
    return path.join(env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'halyard');
  }
  if (platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', 'halyard');
  }
  if (env.XDG_STATE_HOME) return path.join(env.XDG_STATE_HOME, 'halyard');
  return path.join(home, '.local', 'state', 'halyard');
}

// Every runtime file in one place, so `halyard doctor` can print the list and a
// backup is one folder copy. Nothing here is ever served by path from a request
// - see the log-tail route, which keys into a map instead.
function layout(dataDir) {
  const d = (...p) => path.join(dataDir, ...p);
  return {
    root: dataDir,
    config: d('halyard.config.json'),
    token: d('token.txt'),
    state: d('state.json'),
    pushKeys: d('push-keys.json'),
    pushSubs: d('push-subs.json'),
    log: d('halyard.log'),
    replies: d('replies.jsonl'),
    runs: d('runs.jsonl'),
    messages: d('messages.log'),
    lockDir: d('locks'),
    threads: d('threads'),
    artifacts: d('artifacts'),
    uploads: d('uploads'),
  };
}

// Created eagerly at startup rather than lazily at first write: a missing
// artifacts/ directory turns into a 404 on a link the model has already sent to
// the phone, which reads as "the bridge is broken" rather than "not created yet".
function ensure(paths) {
  for (const key of ['root', 'lockDir', 'threads', 'artifacts', 'uploads']) {
    fs.mkdirSync(paths[key], { recursive: true });
  }
  return paths;
}

module.exports = { defaultDataDir, layout, ensure };
