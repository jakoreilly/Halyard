'use strict';
// Phone messages the server answers itself instead of starting an agent run.
//
// A bare "status?" sent to see whether the last message is still going costs a
// whole agent run, usually resuming a long thread, to say what /api/health
// already knows. So a short message that is ONLY a status question is answered
// here from the queue and the run box, free.
//
// Deliberately narrow: the whole message has to match. "any update on the
// deploy" or "what's the status after the last run" has more to it and still
// goes to the agent, which can read the thread. A false match costs a wasted
// reply; a missed match costs one ordinary run.

const STATUS_RE = /^(?:status|any updates?(?: here)?|is it (?:still running|done|finished)|still running|how(?:'| i)?s it going|what'?s running)\s*\??$/i;

function match(message) {
  const m = String(message || '').trim().replace(/[.!]+$/, '');
  if (!m || m.length > 140 || /\n/.test(m)) return null;
  if (STATUS_RE.test(m)) return { kind: 'status' };
  return null;
}

module.exports = { match, STATUS_RE };
