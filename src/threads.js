// Named threads.
//
// A thread is nothing but a (session id, handover summary) pair, so the whole
// feature is a naming scheme over two small files. Everything else - the
// picker, the per-thread reply history, "clear context" - falls out of that.

const fs = require('fs');
const path = require('path');

const DEFAULT_THREAD = 'main';

// An ALLOW-LIST, not an escape.
//
// This string becomes a filename. The only safe way to keep `..`, path
// separators, drive letters, alternate-data-stream colons, trailing dots and
// Windows reserved device names out of it is to permit nothing outside
// [a-z0-9-] and then check what is left. Escaping is a losing game here: every
// escape scheme has an edge case, and the cost of one getting through is an
// arbitrary file write.
function slug(name) {
  const s = String(name == null ? '' : name)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
  // CON, PRN, AUX, NUL, COM1-9, LPT1-9 are opened as devices on Windows no
  // matter what extension you put on them.
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/.test(s)) return `${s}-thread`;
  return s;
}

// Only a name that slugifies to NOTHING falls back to the default. A named
// thread that happens to have no files yet must read as empty, never fall
// through to `main` - that would leak one thread's memory into every mistyped
// name, silently.
function normalize(name) {
  return slug(name) || DEFAULT_THREAD;
}

function filesFor(paths, name) {
  const t = normalize(name);
  return {
    name: t,
    handover: path.join(paths.threads, `${t}.md`),
    session: path.join(paths.threads, `${t}.session`),
  };
}

function readText(file) {
  try {
    return fs.readFileSync(file, 'utf8').trim();
  } catch (e) {
    return '';
  }
}

// Empty counts as absent. A brand-new thread is marked by an empty handover
// file (the file has to exist, or the thread would vanish from the picker
// mid-use), so a caller asking "does this thread have context?" has to get
// `false` for it. Without that, the first message in a new thread announces
// carried-over context and then shows none.
function read(paths, name) {
  const f = filesFor(paths, name);
  const handover = readText(f.handover);
  return {
    name: f.name,
    handover,
    session: readText(f.session),
    exists: handover.length > 0,
  };
}

function write(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, String(text == null ? '' : text), 'utf8');
}

// A "HANDOVER: none" turn truncates the file to empty rather than deleting it.
// The thread list is a directory listing, so deleting the file deletes the
// thread out from under a phone that is currently using it.
function writeHandover(paths, name, text) {
  write(filesFor(paths, name).handover, text || '');
}

function writeSession(paths, name, id) {
  write(filesFor(paths, name).session, String(id || '').trim());
}

function clearSession(paths, name) {
  try { fs.unlinkSync(filesFor(paths, name).session); } catch (e) { /* already gone */ }
}

// "Clear context" has to drop the session id as well as the summary, or it
// hands back a thread that claims to be fresh and then remembers everything.
function clear(paths, name) {
  const f = filesFor(paths, name);
  write(f.handover, '');
  clearSession(paths, name);
  return f.name;
}

function list(paths) {
  let names = [];
  try {
    names = fs.readdirSync(paths.threads)
      .filter((n) => n.endsWith('.md'))
      .map((n) => n.slice(0, -3));
  } catch (e) {
    names = [];
  }
  if (!names.includes(DEFAULT_THREAD)) names.unshift(DEFAULT_THREAD);
  return names.sort((a, b) => (a === DEFAULT_THREAD ? -1 : b === DEFAULT_THREAD ? 1 : a.localeCompare(b)))
    .map((n) => {
      const t = read(paths, n);
      let updated = null;
      try { updated = fs.statSync(filesFor(paths, n).handover).mtimeMs; } catch (e) { /* never written */ }
      return { name: t.name, hasContext: t.exists, hasSession: !!t.session, updated };
    });
}

function remove(paths, name) {
  const t = normalize(name);
  if (t === DEFAULT_THREAD) return false;
  const f = filesFor(paths, t);
  for (const file of [f.handover, f.session]) {
    try { fs.unlinkSync(file); } catch (e) { /* already gone */ }
  }
  return true;
}

module.exports = {
  DEFAULT_THREAD, slug, normalize, filesFor, read, write: writeHandover,
  writeHandover, writeSession, clearSession, clear, list, remove,
};
