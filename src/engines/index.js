// Stream dialects.
//
// An "engine" is a CLI plus a way of reading what it says while it works. The
// CLI half is pure config (command, argument template). This file is the other
// half: one parser per output dialect, each turning a line of the agent's
// stdout into the two things the phone cares about mid-run -
//
//   1. an ACTIVITY label: one short line, "what is it doing right now"
//   2. a DRAFT: the model's own prose, verbatim, so a twenty-minute run reads
//      as answered minutes before it formally finishes
//
// and accumulating the run-level facts (reply, session id, cost, files touched)
// on a shared `result` object.
//
// Contract, and it is worth stating because two callers depend on it:
//   parse(line, result) -> string | null
// The return value is the activity label ONLY. Everything else is written onto
// `result` as a side effect. Activity and draft move INDEPENDENTLY - Copilot
// emits prose on an event that produces no label at all - so the run loop has
// to check both rather than gating one on the other.

// The phone renders activity in a single-line element, so a label with a
// newline in it silently loses everything after the first line.
function oneLine(s, max = 120) {
  const t = String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max)}...` : t;
}

function baseName(p) {
  const s = String(p || '');
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  return i === -1 ? s : s.slice(i + 1);
}

function parseJson(line) {
  const t = String(line || '').trim();
  if (!t || (t[0] !== '{' && t[0] !== '[')) return null;
  try {
    return JSON.parse(t);
  } catch (e) {
    // Agent CLIs interleave the occasional plain-text line (a warning, a
    // progress bar). Skipping it is correct; throwing would end the run.
    return null;
  }
}

function pushUnique(arr, v) {
  if (v && !arr.includes(v)) arr.push(v);
}

// ---------------------------------------------------------------------------
// Claude Code: --output-format stream-json --verbose

function claudeJson(line, result) {
  const evt = parseJson(line);
  if (!evt) return null;

  if (evt.type === 'system' && evt.session_id) result.sessionId = evt.session_id;

  if (evt.type === 'result') {
    if (evt.session_id) result.sessionId = evt.session_id;
    if (evt.result != null) result.reply = String(evt.result);
    // Assigned only when present. `null` is the "the CLI did not report this"
    // signal everywhere downstream, and a cost of 0 is a real value that must
    // stay distinguishable from a missing one - so this is an explicit
    // presence check, never a truthiness check.
    if (evt.total_cost_usd != null) result.costUsd = Number(evt.total_cost_usd);
    if (evt.duration_ms != null) result.durationMs = Number(evt.duration_ms);
    if (evt.num_turns != null) result.numTurns = Number(evt.num_turns);
    if (evt.usage) result.usage = evt.usage;
    if (evt.is_error) result.isError = true;
    return null;
  }

  if (evt.type !== 'assistant') return null;
  const content = (evt.message && evt.message.content) || [];
  let label = null;

  for (const block of content) {
    if (!block || block.type !== 'text') continue;
    const text = String(block.text || '').trim();
    if (!text) continue;
    // The same prose twice, for two different jobs. `lastText` keeps it
    // verbatim - paragraphs intact, nothing clipped - because it feeds the
    // phone's draft panel, which is a block element. The label is the
    // collapsed, clamped version for the one-line activity element.
    result.lastText = text;
    label = `… ${text}`;
  }

  // A tool call in the same message wins over the prose that introduced it:
  // the action is more specific than the preamble.
  for (const block of content) {
    if (!block || block.type !== 'tool_use') continue;
    const input = block.input || {};
    switch (block.name) {
      case 'Edit':
      case 'Write':
      case 'MultiEdit':
      case 'NotebookEdit': {
        const f = String(input.file_path || '');
        if (f) {
          pushUnique(result.filesChanged, f);
          label = `${block.name} ${baseName(f)}`;
        }
        break;
      }
      case 'Read':
        if (input.file_path) label = `Read ${baseName(input.file_path)}`;
        break;
      case 'Bash':
      case 'PowerShell': {
        const cmd = String(input.command || '');
        if (cmd) {
          pushUnique(result.commands, cmd);
          label = `Run ${cmd.length > 60 ? `${cmd.slice(0, 60)}...` : cmd}`;
        }
        break;
      }
      case 'Grep':
      case 'Glob':
        label = `Search ${input.pattern || ''}`;
        break;
      case 'WebFetch':
      case 'WebSearch':
        label = `Web ${input.url || input.query || ''}`;
        break;
      case 'Task':
        label = `Subagent: ${input.description || ''}`;
        break;
      default:
        label = String(block.name || '');
    }
  }

  return label ? oneLine(label) : null;
}

// ---------------------------------------------------------------------------
// GitHub Copilot CLI: --output-format json
//
// Not Claude's shape, and the difference is load-bearing: the final reply is
// the LAST assistant.message whose data.toolRequests is empty, not a field on
// `result` (which carries only sessionId / exitCode / usage). Getting this
// wrong does not error - it silently returns a mid-run tool-call turn as the
// answer.

function copilotJson(line, result) {
  const evt = parseJson(line);
  if (!evt) return null;

  if (evt.type === 'result') {
    if (evt.sessionId) result.sessionId = evt.sessionId;
    if (evt.exitCode != null) result.engineExitCode = Number(evt.exitCode);
    if (evt.usage) result.usage = evt.usage;
    return null;
  }

  if (evt.type === 'assistant.message') {
    const data = evt.data || {};
    const hasTools = Array.isArray(data.toolRequests) && data.toolRequests.length > 0;
    if (!hasTools && data.content != null) {
      result.reply = String(data.content);
    } else if (hasTools && data.content) {
      // Prose on a tool-call turn: this engine's only draft material. Note
      // this branch returns null like the one above, so it posts no activity
      // label - the run loop notices `lastText` moved and sends a draft-only
      // update. Gating drafts on a changed label would mean this engine never
      // produced one.
      result.lastText = String(data.content).trim();
    }
    return null;
  }

  if (evt.type === 'tool.execution_start') {
    const data = evt.data || {};
    const desc = (data.arguments && data.arguments.description) || '';
    return oneLine(desc ? `${data.toolName}: ${desc}` : String(data.toolName || ''));
  }

  return null;
}

// ---------------------------------------------------------------------------
// Anything else: plain text on stdout is the answer.
//
// No activity, no session, no cost - but it makes "point Halyard at my own
// script" a config change rather than a pull request, and it is the worked
// example for writing a real parser.

function plainText(line, result) {
  result.replyLines.push(String(line));
  result.reply = result.replyLines.join('\n');
  return null;
}

const PARSERS = {
  'claude-json': claudeJson,
  'copilot-json': copilotJson,
  text: plainText,
};

function parserFor(streamName) {
  return PARSERS[streamName] || PARSERS.text;
}

// The mutable accumulator every parser writes into. Pre-declared in full, with
// null - not undefined, not 0 - for anything the CLI reports optionally, so
// "not reported" and "reported as zero" stay different answers all the way to
// the footer the phone renders.
function newResult() {
  return {
    reply: '',
    replyLines: [],
    lastText: '',
    sessionId: '',
    costUsd: null,
    durationMs: null,
    numTurns: null,
    usage: null,
    isError: false,
    engineExitCode: null,
    filesChanged: [],
    commands: [],
    exitCode: -1,
    stderr: '',
    killed: false,
    timedOut: false,
  };
}

module.exports = { parserFor, newResult, PARSERS, oneLine, baseName };
