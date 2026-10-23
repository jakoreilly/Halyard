// Which model a message runs on, when the phone did not pin one exactly.
//
// Two decisions, both pure so the tests can pin them without spawning anything:
//
//   Auto      - the phone picked "auto". A message that looks light starts on the
//               engine's light model, one that looks like real work starts on the
//               heavy one. The guess only has to be right about the START: a
//               light turn that finds it needs more answers with a single
//               "ESCALATE: <reason>" line and the watcher retakes the same turn
//               on the heavy model, resuming the session the light one wrote. So
//               the rules lean light - a wrong "light" costs one short turn, not
//               a weak answer.
//
//   Background - nobody is waiting on this run (a repeat, a message queued with
//               `background: true`, or a thread the config names), so a cheaper
//               model is fine. Only ever fills in a missing model; a message that
//               chose one keeps it.

const DEFAULT_WORK_WORDS = [
  'build', 'implement', 'refactor', 'fix', 'debug', 'diagnos\\w*', 'review', 'redesign',
  'migrat\\w*', 'deploy', 'release', 'merge', 'pull request', 'investigat\\w*', 'research',
  'audit', 'bench\\w*', 'install', 'set ?up', 'crash\\w*', 'broken', 'bug', 'failing',
];

function workWordRegex(words) {
  const list = Array.isArray(words) && words.length ? words : DEFAULT_WORK_WORDS;
  return new RegExp(`\\b(${list.join('|')})\\b`, 'i');
}

// -> { tier: 'light' | 'heavy', reason }
function autoTier(message, { hasAttachment = false, workWords, longChars = 600 } = {}) {
  const m = String(message || '').trim();
  if (hasAttachment) return { tier: 'heavy', reason: 'has an attachment' };
  if (m.length > longChars) return { tier: 'heavy', reason: 'long message' };
  const work = workWordRegex(workWords).exec(m);
  if (work) return { tier: 'heavy', reason: `work word '${work[1].toLowerCase()}'` };
  // A go-ahead on something proposed earlier ("1 and 3 please", "yes do it") is
  // short but usually starts the biggest job of the thread.
  if (m.length <= 160 && (/^(yes|yep|yeah|ok(ay)?|go( ahead)?|do (it|that|them|both|all)|please do|all of (them|it)|both)\b/i.test(m)
    || /^\s*(\d+\s*(,|and|&|\+|then)\s*)+\d+\b/i.test(m))) {
    return { tier: 'heavy', reason: 'go-ahead on earlier work' };
  }
  return { tier: 'light', reason: 'looks light' };
}

// The reason from a reply that opens with "ESCALATE: <reason>", else null. Only
// the reply's very first line counts, so a reply that merely talks about
// escalation (or quotes this feature back) never triggers a second run.
function escalation(reply) {
  const m = /^\s*\**ESCALATE:\**\s*([^\r\n]*)/.exec(String(reply || ''));
  if (!m) return null;
  const reason = m[1].trim() || 'no reason given';
  return reason.length > 200 ? reason.slice(0, 200) : reason;
}

function escalateNote(lightLabel) {
  return `MODEL ROUTING: this turn is on ${lightLabel}, picked automatically because the message looked light. `
    + 'If it actually needs substantial work - changing code across files, building or debugging, a careful review, '
    + 'multi-step research, or a judgement call with real consequences - do not attempt it and make no changes: '
    + 'reply with only the line "ESCALATE: <one-line reason>" and no HANDOVER line. A stronger model then takes this '
    + 'same turn with this conversation in view. Otherwise answer normally.';
}

// The model key a message should run on, before Auto is resolved.
function backgroundModel(item, cfg) {
  if (item.model) return item.model;
  const bg = cfg.background || {};
  if (!bg.model) return '';
  const threads = Array.isArray(bg.threads) ? bg.threads : [];
  if (item.background || (bg.repeats && item.repeat) || threads.includes(item.thread)) return bg.model;
  return '';
}

// Everything the watcher needs to start the run: the model key to pass, and
// what to show and say about it.
// -> { model, auto: null | { tier, reason, light, heavy }, label }
function plan(item, engine, cfg) {
  const key = backgroundModel(item, cfg);
  const bg = !item.model && key ? ' (background)' : '';
  if (key === 'auto' && engine.auto && engine.auto.light && engine.auto.heavy) {
    const t = autoTier(item.message, { hasAttachment: !!item.attachment, workWords: engine.auto.workWords });
    const model = t.tier === 'heavy' ? engine.auto.heavy : engine.auto.light;
    return { model, auto: { ...t, light: engine.auto.light, heavy: engine.auto.heavy }, label: `${model} (auto)` };
  }
  // An engine with no Auto block treats "auto" as "default model".
  if (key === 'auto') return { model: '', auto: null, label: '' };
  return { model: key, auto: null, label: key ? `${key}${bg}` : '' };
}

module.exports = { autoTier, escalation, escalateNote, backgroundModel, plan, DEFAULT_WORK_WORDS };
