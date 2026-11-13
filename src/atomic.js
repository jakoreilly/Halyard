
const fs = require('fs');

function writeFileAtomic(file, data, opts) {
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, data, opts);
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (e2) { /* never created, or already gone */ }
    if (!['EPERM', 'EBUSY', 'EACCES'].includes(e.code)) throw e;
    fs.writeFileSync(file, data, opts);
  }
}

module.exports = { writeFileAtomic };
