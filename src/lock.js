// One run at a time, per engine.
//
// The watcher can be nudged by the server the moment a message arrives AND by
// its own interval timer AND by an external `halyard watch` invocation. Without
// a lock, two of those pop two different messages and then race on the same
// thread's session file - one turn's context silently disappears, and nothing
// anywhere reports it.
//
// Implementation notes that matter:
//
//   - `wx` (O_CREAT|O_EXCL) is the only cross-platform atomic "create if it does
//     not exist". Not exists-then-create: that is a race with itself.
//   - The PID goes IN the file. A stale lock from a crashed process is the
//     common case, and being able to ask "is 41234 still alive?" turns a
//     30-minute wait into an instant recovery.
//   - The age fallback exists because a PID can be reused. If the process at
//     that PID is alive but the lock is older than the run timeout, it is
//     treated as stale anyway - a run that outlived its own budget is not a run
//     worth protecting.
//   - Release is idempotent and never throws. It is called from a finally block
//     whose whole job is to make sure the next run can start.

const fs = require('fs');
const path = require('path');

function isAlive(pid) {
  if (!pid || !Number.isInteger(pid)) return false;
  try {
    // Signal 0 performs the permission/existence check without delivering
    // anything. On Windows, node maps this to an OpenProcess check.
    process.kill(pid, 0);
    return true;
  } catch (e) {
    // EPERM means it exists but belongs to someone else - still alive.
    return e.code === 'EPERM';
  }
}

function read(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return null;
  }
}

// Returns a release function on success, or null if someone else holds it.
function acquire(lockDir, name, { maxAgeMs = 30 * 60 * 1000, log } = {}) {
  const file = path.join(lockDir, `${name}.lock`);
  fs.mkdirSync(lockDir, { recursive: true });

  const body = JSON.stringify({ pid: process.pid, at: Date.now() });

  const tryCreate = () => {
    try {
      fs.writeFileSync(file, body, { flag: 'wx' });
      return true;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      return false;
    }
  };

  if (!tryCreate()) {
    const held = read(file);
    let stale = false;
    let why = '';
    if (!held) {
      stale = true;
      why = 'unreadable lock file';
    } else if (!isAlive(held.pid)) {
      stale = true;
      why = `holder pid ${held.pid} is gone`;
    } else if (Date.now() - (held.at || 0) > maxAgeMs) {
      stale = true;
      why = `held for ${Math.round((Date.now() - held.at) / 60000)}m, past the ${Math.round(maxAgeMs / 60000)}m limit`;
    }
    if (!stale) return null;
    if (log) log.warn(`clearing stale lock ${name}: ${why}`);
    try { fs.unlinkSync(file); } catch (e) { /* someone else won the race; the retry below decides */ }
    if (!tryCreate()) return null;
  }

  let released = false;
  return function release() {
    if (released) return;
    released = true;
    try {
      // Only remove it if it is still ours. A lock we were reaped out of
      // belongs to the process that reaped us.
      const held = read(file);
      if (!held || held.pid === process.pid) fs.unlinkSync(file);
    } catch (e) {
      // Nothing useful to do here, and throwing from a finally would mask the
      // real error that sent us there.
    }
  };
}

function inspect(lockDir, name) {
  const file = path.join(lockDir, `${name}.lock`);
  if (!fs.existsSync(file)) return null;
  const held = read(file) || {};
  return {
    name,
    pid: held.pid || null,
    at: held.at || null,
    ageMs: held.at ? Date.now() - held.at : null,
    alive: isAlive(held.pid),
  };
}

module.exports = { acquire, inspect, isAlive };
