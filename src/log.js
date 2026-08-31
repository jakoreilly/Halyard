// Logging: one line per event, to a file and (at info+) to stdout.
//
// Rotated by size rather than by date because the interesting failure is a
// tight retry loop producing megabytes in minutes, and a daily rotation does
// nothing about that. Rotation is best-effort: a failure to rotate must never
// take the bridge down, since the bridge is often the only way to find out
// something went wrong.

const fs = require('fs');
const path = require('path');

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MAX_BYTES = 8 * 1024 * 1024;

function createLogger(file, level = 'info') {
  const min = LEVELS[level] || LEVELS.info;

  function rotate() {
    try {
      const st = fs.statSync(file);
      if (st.size < MAX_BYTES) return;
      fs.renameSync(file, `${file}.1`);
    } catch (e) {
      // ENOENT on first write is the normal case, not a problem.
    }
  }

  function write(lvl, msg, extra) {
    if (LEVELS[lvl] < min) return;
    const line = JSON.stringify({
      t: new Date().toISOString(),
      lvl,
      msg: String(msg),
      ...(extra && typeof extra === 'object' ? extra : {}),
    });
    if (LEVELS[lvl] >= LEVELS.info) {
      (lvl === 'error' || lvl === 'warn' ? process.stderr : process.stdout).write(`${line}\n`);
    }
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      rotate();
      fs.appendFileSync(file, `${line}\n`);
    } catch (e) {
      // Losing a log line is strictly better than crashing the process that
      // was trying to record why something else went wrong.
    }
  }

  return {
    file,
    debug: (m, e) => write('debug', m, e),
    info: (m, e) => write('info', m, e),
    warn: (m, e) => write('warn', m, e),
    error: (m, e) => write('error', m, e),
  };
}

module.exports = { createLogger, LEVELS };
