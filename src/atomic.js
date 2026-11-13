// Write-then-rename, for files whose loss is silent.
//
// state.json was written in place. A crash or power cut mid-write left
// truncated JSON, loadState logged a warning and started empty, and the queue,
// every scheduled repeat and the retryable failure were gone with nothing on
// the phone to say so. A rename is atomic on every platform node runs on: a
// reader sees the old file or the new one, never half of either.

const fs = require('fs');

function writeFileAtomic(file, data, opts) {
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, data, opts);
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (e2) { /* never created, or already gone */ }
    // On Windows a rename over a file that antivirus or another reader has
    // open fails with EPERM/EBUSY/EACCES. Falling back to the old in-place
    // write is never worse than what this replaced; throwing would lose the
    // write entirely.
    if (!['EPERM', 'EBUSY', 'EACCES'].includes(e.code)) throw e;
    fs.writeFileSync(file, data, opts);
  }
}

module.exports = { writeFileAtomic };
