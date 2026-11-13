
const fs = require('fs');
const path = require('path');
const { writeFileAtomic } = require('./atomic');

function archiveDir(file) {
  return path.join(path.dirname(file), 'archive');
}

function rotated(file) {
  const base = path.basename(file, '.jsonl');
  const re = new RegExp(`^${base}-(\\d+)(?:-\\d+)?\\.jsonl$`);
  let names = [];
  try { names = fs.readdirSync(archiveDir(file)); } catch (e) { return []; }
  return names
    .map((n) => ({ n, m: re.exec(n) }))
    .filter((x) => x.m)
    .sort((a, b) => Number(b.m[1]) - Number(a.m[1]) || (a.n < b.n ? 1 : -1))
    .map((x) => path.join(archiveDir(file), x.n));
}

function append(file, obj, maxBytes) {
  try {
    fs.appendFileSync(file, `${JSON.stringify(obj)}\n`);
    if (fs.statSync(file).size > maxBytes) {
      fs.mkdirSync(archiveDir(file), { recursive: true });
      const stem = `${path.basename(file, '.jsonl')}-${Date.now()}`;
      let target = path.join(archiveDir(file), `${stem}.jsonl`);
      for (let n = 2; fs.existsSync(target); n++) target = path.join(archiveDir(file), `${stem}-${n}.jsonl`);
      fs.renameSync(file, target);
    }
  } catch (e) {
  }
}

function readFile(file) {
  const out = [];
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { return out; }
  for (const line of text.split('\n')) {
    if (!line) continue;
    try { out.push(JSON.parse(line)); } catch (e) { /* skip a torn line */ }
  }
  return out;
}

function readAll(file, { maxFiles = 12 } = {}) {
  const old = rotated(file);
  const take = old.slice(0, Math.max(0, maxFiles));
  let items = readFile(file);
  for (const f of take) items = items.concat(readFile(f));
  return { items, truncated: old.length > take.length };
}

function removeById(file, id) {
  let removed = 0;
  for (const f of [file].concat(rotated(file))) {
    const before = readFile(f);
    const kept = before.filter((n) => n.id !== id);
    if (kept.length === before.length) continue;
    removed += before.length - kept.length;
    writeFileAtomic(f, kept.map((n) => JSON.stringify(n)).join('\n') + (kept.length ? '\n' : ''));
  }
  return removed;
}

module.exports = { append, readAll, removeById, rotated };
