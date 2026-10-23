// Shrinks a thread's Claude Code transcript so the conversation survives longer.
//
// A thread resumes a real CLI session (`--resume <id>`), and the whole transcript
// comes back with it - every `git status`, every build log, every file read. Tool
// output is routinely a third of it while the conversation itself is a few
// percent. This removes the bulk and leaves the talking. docs/TRANSCRIPT-PRUNING.md
// has the measurements and the reasoning behind each rule; in short:
//
// - It never deletes a content block. A tool_use with no matching tool_result (or
//   the reverse) is a malformed conversation, and the API rejects the whole
//   request. Shrinking a result in place is safe; dropping it is not.
// - Tool output is stored TWICE: the tool_result block and a top-level
//   toolUseResult copy that is usually bigger. Both are pruned.
// - It never writes over the original. The pruned copy gets a new session id, so
//   undoing it is pointing the thread back at the old id.
//
// The transcript format is undocumented and can change under a CLI update, which
// is why verify() runs before anything is written.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_MAX = 2000;
const DEFAULT_KEEP = 300;

function human(bytes) {
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${bytes} B`;
}

function stub(original) {
  return `\n\n[pruned by halyard: ${human(original)} of tool output removed. `
    + 'The full output is in the original transcript; ask again if it still matters.]';
}

// Prunes one parsed line in place. Returns bytes saved.
function pruneLine(obj, opts) {
  let saved = 0;
  const content = obj.message && obj.message.content;
  if (Array.isArray(content)) {
    for (const block of content) {
      if (!block || block.type !== 'tool_result') continue;
      if (typeof block.content === 'string') {
        if (block.content.length <= opts.max) continue;
        const before = block.content.length;
        block.content = block.content.slice(0, opts.keep) + stub(before);
        saved += before - block.content.length;
      } else if (Array.isArray(block.content)) {
        // Only text parts: an image block with its data removed is not a smaller
        // image, it is a broken block.
        for (const part of block.content) {
          if (!part || part.type !== 'text' || typeof part.text !== 'string' || part.text.length <= opts.max) continue;
          const before = part.text.length;
          part.text = part.text.slice(0, opts.keep) + stub(before);
          saved += before - part.text.length;
        }
      }
    }
  }
  if (obj.toolUseResult !== undefined) {
    const before = JSON.stringify(obj.toolUseResult).length;
    if (before > opts.max) {
      obj.toolUseResult = { pruned: true, originalBytes: before };
      saved += before - JSON.stringify(obj.toolUseResult).length;
    }
  }
  return saved;
}

function prune(raw, { max = DEFAULT_MAX, keep = DEFAULT_KEEP, sessionId = null } = {}) {
  const lines = String(raw).split('\n').filter((l) => l.trim());
  const out = [];
  for (const line of lines) {
    let obj;
    try { obj = JSON.parse(line); } catch (e) {
      // Far more likely a format this has not seen than something worth deleting.
      out.push(line);
      continue;
    }
    pruneLine(obj, { max, keep });
    if (sessionId) obj.sessionId = sessionId;
    out.push(JSON.stringify(obj));
  }
  const body = `${out.join('\n')}\n`;
  const beforeBytes = Buffer.byteLength(String(raw));
  const afterBytes = Buffer.byteLength(body);
  const savedPercent = beforeBytes ? ((beforeBytes - afterBytes) / beforeBytes) * 100 : 0;
  return { body, beforeBytes, afterBytes, savedPercent };
}

// Every tool_use still has its tool_result and vice versa - the one thing that
// would break a resume. One dangling call at the very end is the turn in progress.
function verify(body) {
  const calls = new Set();
  const results = new Set();
  for (const line of String(body).split('\n')) {
    if (!line.trim()) continue;
    let obj;
    try { obj = JSON.parse(line); } catch (e) { continue; }
    const content = obj.message && obj.message.content;
    if (!Array.isArray(content)) continue;
    for (const b of content) {
      if (b && b.type === 'tool_use' && b.id) calls.add(b.id);
      if (b && b.type === 'tool_result' && b.tool_use_id) results.add(b.tool_use_id);
    }
  }
  const orphans = [...results].filter((id) => !calls.has(id));
  const unanswered = [...calls].filter((id) => !results.has(id));
  if (orphans.length) return { ok: false, reason: `${orphans.length} tool_result blocks lost their tool_use` };
  if (unanswered.length > 1) return { ok: false, reason: `${unanswered.length} tool_use blocks have no result` };
  return { ok: true };
}

// Where the CLI keeps a session's transcript. Its own folder naming (every
// non-alphanumeric character of the cwd becomes '-') is tried first, then every
// project folder, because that naming is undocumented and has changed before.
function findTranscript(sessionId, cwd, root = path.join(os.homedir(), '.claude', 'projects')) {
  if (!/^[A-Za-z0-9-]+$/.test(String(sessionId || ''))) return null;
  const name = `${sessionId}.jsonl`;
  const guesses = [String(cwd || '').replace(/[^A-Za-z0-9]/g, '-'), String(cwd || '').replace(/[\\/:]/g, '-')];
  for (const g of guesses) {
    const f = path.join(root, g, name);
    if (g && fs.existsSync(f)) return f;
  }
  let dirs = [];
  try { dirs = fs.readdirSync(root); } catch (e) { return null; }
  for (const d of dirs) {
    const f = path.join(root, d, name);
    if (fs.existsSync(f)) return f;
  }
  return null;
}

// Prune a session into a new one if that saves at least minPercent.
// -> { applied, newSessionId?, savedPercent?, note }
function shrinkSession(sessionId, cwd, { minPercent = 15, root } = {}) {
  const file = findTranscript(sessionId, cwd, root);
  if (!file) return { applied: false, note: 'no transcript found' };
  const raw = fs.readFileSync(file, 'utf8');
  const dry = prune(raw);
  if (dry.savedPercent < minPercent) return { applied: false, savedPercent: dry.savedPercent, note: `would save only ${Math.round(dry.savedPercent)}%` };
  const newSessionId = crypto.randomUUID();
  const real = prune(raw, { sessionId: newSessionId });
  const v = verify(real.body);
  if (!v.ok) return { applied: false, note: `pairing check failed: ${v.reason}` };
  fs.writeFileSync(path.join(path.dirname(file), `${newSessionId}.jsonl`), real.body);
  return { applied: true, newSessionId, savedPercent: real.savedPercent, note: `saved ${Math.round(real.savedPercent)}%` };
}

module.exports = { prune, pruneLine, verify, findTranscript, shrinkSession };
