// The watcher: takes one message off the queue, runs the agent, sends the
// answer back.
//
// This is a from-scratch Node implementation of a loop that previously existed
// as ~1,000 lines of Windows PowerShell. Almost every non-obvious thing in here
// is a bug that has actually happened, so the comments say which one.
//
// The load-bearing invariants, in order of how expensive they are to relearn:
//
//   1. THE PROMPT GOES IN ON STDIN, NEVER AS AN ARGUMENT. Passing a
//      multi-paragraph prompt as argv works right up until it contains a quote
//      character, at which point some platforms' native-argument re-parsing
//      strips the quote and splits on the next whitespace. The prompt arrives
//      truncated, the model answers the truncated question, and nothing
//      anywhere reports an error. Worse, if the truncated turn writes a
//      handover summary, the truncation persists into every later turn.
//
//   2. A POPPED MESSAGE MUST ALWAYS PRODUCE A REPLY. The pop is destructive and
//      there is no re-queue. Once we have popped, the phone is waiting on THIS
//      run and nothing else will ever answer it, so every path from the pop
//      onwards either replies or reports a failure the phone can retry.
//
//   3. EVERY WAIT IS BOUNDED. A grandchild process that inherited the agent's
//      stdout (a shell left behind by a tool call) holds the pipe open after
//      the agent itself has exited. An unbounded read there waits forever while
//      holding the run lock, and the whole bridge is wedged until a human kills
//      the process by hand. Both stdout and stderr get the same bound, because
//      fixing only stdout just moves the hang one line down.

const { spawn, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const { parserFor, newResult } = require('./engines');
const lock = require('./lock');
const { workspaceFor } = require('./config');
const threads = require('./threads');
const router = require('./router');
const prunemod = require('./prune');
const usagemod = require('./usage');
const { resolveCommand } = require('./which');

// ---------------------------------------------------------------------------
// Argument templates

// Substitutes {{placeholders}} and drops any flag whose value came out empty.
// One template can then cover "no model selected" and "first message in a
// thread, so no session to resume" without a combinatorial set of templates.
function buildArgs(template, vars) {
  const out = [];
  for (const raw of template || []) {
    const whole = /^\{\{(\w+)\}\}$/.exec(String(raw));
    if (whole) {
      const val = vars[whole[1]];
      if (val === undefined || val === null || val === '') {
        // Drop the flag this value belonged to, if the previous token looks
        // like one. `--model` with nothing after it is not a smaller request,
        // it is a usage error that fails the whole run.
        if (out.length && /^--?[\w][\w-]*$/.test(out[out.length - 1])) out.pop();
        continue;
      }
      out.push(String(val));
      continue;
    }
    out.push(String(raw).replace(/\{\{(\w+)\}\}/g, (_, k) => (vars[k] == null ? '' : String(vars[k]))));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Running the agent

// Stop and the run budget have to take the agent's children with it. On
// Windows child.kill() ends only the direct process, so the shell or dev
// server a tool call started keeps running after the phone was told the run
// stopped - and keeps the pipes open, so the run then sits out the whole
// post-exit bound as well. taskkill /T walks the tree. POSIX keeps the plain
// kill: a process-group kill needs the agent spawned detached, which would
// also stop a Ctrl+C on `halyard start` from reaching it.
function killTree(child) {
  if (process.platform === 'win32' && child.pid) {
    try {
      const tk = spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
      tk.on('error', () => { try { child.kill('SIGKILL'); } catch (e) { /* already dead */ } });
      return;
    } catch (e) {
      // Fall through to the plain kill.
    }
  }
  try { child.kill('SIGKILL'); } catch (e) { /* already dead */ }
}

// The hooks run inside the agent's process tree, not inside Halyard, so the
// only things they know about this install are what reaches them through the
// environment. Without these they fall back to port 4545 and the default data
// dir: on any other port, or with --data-dir, every relayed command is denied
// as "Halyard unreachable", and relay.timeoutMs and relay.rules from the config
// file never take effect at all. `halyard ask` run by the agent reads the same
// variables through the normal config layering.
function hookEnv({ cfg, paths, client }) {
  const env = {
    HALYARD_DATA_DIR: paths.root,
    HALYARD_PORT: String(cfg.port),
  };
  // The client's base already maps a wildcard bind onto loopback and brackets
  // an IPv6 host, so the hooks reach exactly what the watcher reaches.
  if (client && client.base) env.HALYARD_URL = client.base;
  const relay = cfg.relay || {};
  if (Number.isFinite(Number(relay.timeoutMs)) && Number(relay.timeoutMs) > 0) {
    env.HALYARD_RELAY_TIMEOUT_MS = String(Math.trunc(Number(relay.timeoutMs)));
  }
  // An empty list is left unset rather than passed as '', although the hook
  // reads both as "all rules" - absent is the one reading nothing can get wrong.
  if (Array.isArray(relay.rules) && relay.rules.length) env.HALYARD_RELAY_RULES = relay.rules.join(',');
  if (relay.privateMergeWithoutTap === true) env.HALYARD_RELAY_PRIVATE_MERGE = '1';
  return env;
}

const PERMISSION_MCP = path.join(__dirname, '..', 'hooks', 'permission-mcp.js');

function permissionPromptArgs({ cfg, engine, paths, env }) {
  const relay = cfg.relay || {};
  if (!relay.enabled || relay.permissionPrompts === false || !engine.supportsRelayHook || !paths.root) {
    return { relayMcpConfig: '', relayPromptTool: '' };
  }
  const { SERVER_NAME, TOOL_NAME } = require('../hooks/permission-mcp');
  const file = path.join(paths.root, 'permission-mcp.json');
  const body = {
    mcpServers: {
      [SERVER_NAME]: { type: 'stdio', command: process.execPath, args: [PERMISSION_MCP], env },
    },
  };
  try {
    fs.writeFileSync(file, JSON.stringify(body, null, 2));
  } catch (e) {
    return { relayMcpConfig: '', relayPromptTool: '' };
  }
  return { relayMcpConfig: file, relayPromptTool: `mcp__${SERVER_NAME}__${TOOL_NAME}` };
}

// Resolves when the agent is finished AND we have stopped waiting for its
// pipes - whichever of those comes first, subject to the bounds above.
function runAgent(opts) {
  const {
    command, args, cwd, prompt, parse, result,
    postExitTimeoutMs = 20000, runTimeoutMs = 30 * 60 * 1000,
    env = {}, onActivity = () => {}, isKillRequested = async () => false,
    log,
  } = opts;

  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(command, args, {
        cwd,
        // No shell. The prompt is on stdin and every argument is passed as its
        // own argv entry, so there is nothing here a shell would help with -
        // and a shell is one more layer that can re-parse and mangle them.
        shell: false,
        // Without this a console-subsystem agent binary gets its own flashing
        // window on every run on Windows, even though its streams are all
        // redirected.
        windowsHide: true,
        env: {
          ...process.env,
          ...env,
          // Tells the pre-tool hook that this run is unattended, so the relay
          // arms itself. The hook can also infer it from the permission mode
          // the agent reports, but that is the agent's word for it and this is
          // ours: it survives an agent renaming its modes, dropping the field,
          // or adding a bypass-equivalent the hook has never heard of. Set at
          // this single choke point rather than per call site, because a
          // marker that can be forgotten somewhere is a backstop that silently
          // is not there.
          HALYARD_HEADLESS: '1',
        },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (e) {
      result.exitCode = -1;
      result.stderr = `failed to spawn ${command}: ${e.message}`;
      return resolve(result);
    }

    let settled = false;
    let exitTimer = null;
    let killPoll = null;
    let hardTimer = null;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(exitTimer);
      clearTimeout(hardTimer);
      clearInterval(killPoll);
      // Actively tear the pipes down. If a grandchild is still holding them,
      // nothing else will ever close them and the node process would stay
      // alive with the run lock held.
      try { child.stdout.destroy(); } catch (e) { /* already gone */ }
      try { child.stderr.destroy(); } catch (e) { /* already gone */ }
      resolve(result);
    };

    child.on('error', (e) => {
      result.stderr = `${result.stderr}\n[halyard] spawn error: ${e.message}`.trim();
      result.exitCode = -1;
      finish();
    });

    // --- stdin: the prompt, and only the prompt -----------------------------
    child.stdin.on('error', (e) => {
      // EPIPE here means the agent exited before reading its prompt. That is a
      // real failure, but it surfaces through the exit code; throwing from an
      // stdin error handler would take the whole process down instead.
      if (log) log.debug(`stdin closed early: ${e.message}`);
    });
    child.stdin.end(prompt, 'utf8');

    // --- stdout: line-buffered, parsed as it arrives ------------------------
    let buf = '';
    let lastActivity = null;
    let lastDraft = null;

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      buf += chunk;
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl).replace(/\r$/, '');
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let activity = null;
        try {
          activity = parse(line, result);
        } catch (e) {
          // A parser throwing on one malformed line must not end a run that is
          // otherwise going fine. The reply comes from the terminal event, and
          // this line was not it.
          if (log) log.debug(`parse error: ${e.message}`);
        }
        const draft = result.lastText || '';
        const activityChanged = activity && activity !== lastActivity;
        const draftChanged = draft && draft !== lastDraft;
        // Checked independently, because the two do not move together: some
        // engines emit prose on an event that produces no activity label at
        // all, so gating the draft on a changed label means that engine never
        // sends one. And a stretch of pure tool calls must leave the previous
        // draft standing rather than blanking it.
        if (activityChanged || draftChanged) {
          if (activityChanged) lastActivity = activity;
          if (draftChanged) lastDraft = draft;
          // Only the parts that actually changed. Re-sending an unchanged
          // label appends a duplicate transcript line for what was one event.
          onActivity({
            activity: activityChanged ? activity : undefined,
            draft: draftChanged ? draft : undefined,
          });
        }
      }
    });
    child.stdout.on('end', () => {
      if (buf.trim()) {
        try { parse(buf.trim(), result); } catch (e) { /* last partial line */ }
      }
      // Genuine EOF. If the process has already gone, we are done; if not, the
      // exit handler below will finish us.
      if (child.exitCode !== null || child.signalCode) finish();
    });

    // --- stderr: diagnostic only, and expendable ----------------------------
    let errBuf = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (c) => {
      // Bounded so a chatty agent cannot grow this without limit; only the
      // tail matters for the checks that read it.
      errBuf = (errBuf + c).slice(-64 * 1024);
      result.stderr = errBuf;
    });

    // --- exit: start the clock on the pipes ---------------------------------
    child.on('exit', (code, signal) => {
      result.exitCode = code === null ? -1 : code;
      if (signal) result.stderr = `${result.stderr}\n[halyard] killed with ${signal}`.trim();
      clearInterval(killPoll);
      // EOF alone is not a sufficient exit condition, so give the pipes a
      // bounded grace period to drain and then stop waiting regardless. On a
      // healthy run 'end' fires within milliseconds and this never expires.
      exitTimer = setTimeout(() => {
        result.stderr = `${result.stderr}\n[halyard] stdout was still open ${Math.round(postExitTimeoutMs / 1000)}s after exit (a lingering child process is holding it); stopped waiting.`.trim();
        finish();
      }, postExitTimeoutMs);
      // If the pipes are already closed we do not need the grace period.
      if (child.stdout.destroyed && child.stderr.destroyed) finish();
    });

    // --- the two ways a run ends early --------------------------------------
    hardTimer = setTimeout(() => {
      result.timedOut = true;
      killTree(child);
      // Do not resolve here. The exit handler runs next and applies the same
      // bounded drain, so a reply that had already been emitted is still read.
    }, runTimeoutMs);

    killPoll = setInterval(async () => {
      try {
        if (!result.killed && await isKillRequested()) {
          result.killed = true;
          killTree(child);
        }
      } catch (e) {
        // A health check failing is not a reason to kill a working run.
      }
    }, 2000);
  });
}

// ---------------------------------------------------------------------------
// Prompt assembly

function buildPrompt({ item, thread, engine, cfg, secretsDir, routingNote, workspace }) {
  const parts = [];
  parts.push(
    'You are answering a message sent from a phone through Halyard, a local bridge to this machine.',
    '',
    `Working directory: ${workspace || cfg.workspace}`,
    `Permission mode: ${cfg.permissionMode}`,
    cfg.relay && cfg.relay.enabled && engine.supportsRelayHook
      ? `Mutating git commands, recursive deletes and outbound network calls are relayed to the phone for an approve/deny tap before they run.${cfg.relay.permissionPrompts === false ? '' : ' So is anything else that needs permission, such as a shell command outside the allow list.'} Use them normally; expect one pause.`
      : 'There is no approve/deny relay on this engine. Be conservative with anything destructive or outbound.',
    // Only the directory, never a list of names or values: the model is told
    // where to look, and looks only when a message needs a credential.
    ...(secretsDir ? [
      `Secrets the phone saved outside the chat are files in ${secretsDir}. Use one by path and never print, echo or quote its contents. To hand a value to the phone, write it to ${path.join(secretsDir, 'outbox')} and tell the phone to open /secrets - it is deleted once collected. Never ask the phone to paste a credential into a message.`,
    ] : []),
    '',
    'Reply concisely - the answer is read on a phone screen. Prefer doing the work and reporting what you did over asking whether you should. If a message is genuinely ambiguous between two real interpretations - not merely underspecified - check the message log and any carried context first; if it is still ambiguous, run `halyard ask "<question>" --options "a|b"` (give the tool call a long timeout) and continue this same turn with the answer, rather than guessing or ending the turn with a question of your own.',
  );
  if (thread.handover) {
    parts.push(
      '',
      '--- Context carried over from the previous message in this thread ---',
      thread.handover,
      '--- end of carried context ---',
    );
  }
  parts.push(
    '',
    `New message from phone (thread "${thread.name}"):`,
    item.message,
    ...(routingNote ? ['', routingNote] : []),
    '',
    'When you have finished, end your reply with a line starting exactly "HANDOVER:" followed by 2-4 sentences worth carrying into the next message in this thread, or "HANDOVER: none".',
  );
  return parts.join('\n');
}

// The handover convention: the model writes its own continuity note as the last
// line of its reply, and we strip it before the phone ever sees it. Parsed off
// the LAST occurrence, because a reply that quotes the instruction earlier
// (perfectly common when the message is about Halyard itself) would otherwise
// have its own explanation mistaken for the summary.
function splitHandover(reply) {
  const text = String(reply || '');
  const idx = text.lastIndexOf('\nHANDOVER:');
  const at = idx === -1 && text.startsWith('HANDOVER:') ? 0 : idx;
  if (at === -1) return { body: text.trim(), handover: null };
  const body = text.slice(0, at).trim();
  const note = text.slice(at).replace(/^\s*HANDOVER:\s*/, '').trim();
  return { body, handover: /^none$/i.test(note) ? '' : note };
}

// The footer is cosmetic and built from model-supplied paths, so it lives in
// its own try/catch: letting it throw on a malformed path would send the whole
// turn to the outer failure handler and replace a perfectly good reply with
// "the watcher failed".
function changeFooter(result) {
  try {
    const bits = [];
    if (result.filesChanged.length) {
      bits.push(`Edited ${result.filesChanged.length} file${result.filesChanged.length === 1 ? '' : 's'}`);
    }
    const gitCmds = result.commands.filter((c) => /(?<!\w)git\s/.test(c));
    if (gitCmds.length) bits.push(`Git: ${gitCmds.length} command${gitCmds.length === 1 ? '' : 's'}`);
    // null is "the engine did not report this". A run that genuinely cost
    // nothing is a real result and must not look identical to a missing field.
    if (result.costUsd != null) bits.push(`$${result.costUsd.toFixed(4)}`);
    if (result.durationMs != null) bits.push(`${Math.round(result.durationMs / 1000)}s`);
    if (result.numTurns != null) bits.push(`${result.numTurns} turns`);
    if (result.contextTokens) bits.push(`${(result.contextTokens / 1000).toFixed(1)}k context`);
    const notes = (result.notes || []).filter(Boolean);
    if (!bits.length && !notes.length) return '';
    return `\n\n---\n${[bits.join(' · '), ...notes].filter(Boolean).join('\n')}`;
  } catch (e) {
    return '';
  }
}

// ---------------------------------------------------------------------------
// Cross-engine failover
//
// Pure and independently testable, same style as `nextOccurrence` and
// `matchRelayRule` elsewhere in this codebase - no process spawn needed to
// exercise the decision.
//
// Two triggers, both meaning "this engine looks unable to answer right now"
// rather than "this specific message is bad": a silent death (a non-zero exit
// with literally nothing on stderr and no reply - consistent with an
// environment/auth/quota failure that never got as far as writing a message),
// or stderr that reads like a rate limit, quota or auth problem. A user-
// requested Stop or a run that hit its own time budget are neither of those -
// they are not "this engine is down", so the caller checks `result.killed`/
// `result.timedOut` before ever reaching this function.
const CAPACITY_OR_AUTH = /rate.?limit|usage limit|quota|too many requests|\b429\b|\b401\b|unauthorized|authentication|billing/i;

function decideReroute({ item, cfg, engineName, result }) {
  const f = cfg.failover;
  if (!f || !f.enabled || !f.to || f.to === engineName || !cfg.engines[f.to]) return null;
  // Already hopped once. Two engines that both fail on the same message would
  // otherwise ping-pong it forever, burning a full run on each hop.
  if (item.rerouted) return null;
  if (result.reply) return null;
  const silent = result.exitCode !== 0 && !String(result.stderr || '').trim();
  const looksDown = CAPACITY_OR_AUTH.test(result.stderr || '');
  if (!silent && !looksDown) return null;
  return { to: f.to, reason: silent ? `${engineName} exited silently` : `${engineName} looks rate-limited or unauthenticated` };
}

// ---------------------------------------------------------------------------
// One turn

function activitySender(post) {
  let labels = [];
  let draft;
  let busy = false;
  async function pump() {
    busy = true;
    while (labels.length || draft !== undefined) {
      const body = { activities: labels, draft };
      labels = [];
      draft = undefined;
      await post(body);
    }
    busy = false;
  }
  return ({ activity, draft: d }) => {
    if (activity) labels.push(activity);
    if (d !== undefined) draft = d;
    if (!busy) pump();
  };
}

function gitOut(args, cwd, { timeoutMs = 10000, maxBytes = 512 * 1024 } = {}) {
  return new Promise((resolve) => {
    execFile('git', args, { cwd, timeout: timeoutMs, maxBuffer: maxBytes, windowsHide: true },
      (err, stdout) => resolve(err ? null : String(stdout)));
  });
}

function diffHtml({ runId, thread, stat, patch, untracked }) {
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>Diff ${esc(runId)}</title>
<style>body{font:14px/1.5 system-ui,sans-serif;margin:16px;max-width:1100px}pre{font:12.5px/1.45 ui-monospace,Consolas,monospace;overflow-x:auto;white-space:pre}h1{font-size:18px;font-weight:600}h2{font-size:13px;font-weight:500;opacity:.7}</style>
</head><body><main>
<h1>Changes from the run in ${esc(thread)}</h1>
<h2>summary</h2><pre>${esc(stat || '(no tracked changes)')}</pre>
${untracked.length ? `<h2>new files, not yet tracked</h2><pre>${esc(untracked.join('\n'))}</pre>` : ''}
<h2>patch</h2><pre>${esc(patch || '(empty)')}</pre>
</main></body></html>`;
}

async function writeDiff({ cfg, paths, runId, thread, headBefore, workspace }) {
  const d = cfg.diff || {};
  if (!d.enabled || !headBefore) return null;
  try {
    const opts = { timeoutMs: d.timeoutMs, maxBytes: d.maxBytes };
    const stat = await gitOut(['diff', '--no-color', '--stat', headBefore], workspace, opts);
    const patch = await gitOut(['diff', '--no-color', headBefore], workspace, opts);
    const status = await gitOut(['status', '--porcelain'], workspace, opts);
    const untracked = String(status || '').split('\n').filter((l) => l.startsWith('?? ')).map((l) => l.slice(3));
    if (stat === null) return null;
    if (patch === null) return 'Diff too large to attach.';
    if (!patch.trim() && !untracked.length) return null;
    const name = `diff-${runId}.html`;
    fs.writeFileSync(path.join(paths.artifacts, name), diffHtml({ runId, thread, stat, patch, untracked }));
    return `Diff: /artifacts/${name}`;
  } catch (e) {
    return null;
  }
}

async function processOne(ctx, item) {
  const { cfg, client, paths, log } = ctx;
  const engineName = cfg.engines[item.engine] ? item.engine : cfg.defaultEngine;
  const engine = cfg.engines[engineName];
  const thread = threads.read(paths, item.thread);
  const workspace = workspaceFor(cfg, thread.name);
  const runId =`${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  // Auto and the background model are resolved here, once, so the run box, the
  // --model flag and the reply's metadata all name the same model.
  const route = router.plan(item, engine, cfg);
  let modelKey = route.model;

  await client.tryPost('/api/run/start', {
    runId, engine: engineName, thread: thread.name, message: item.message, model: modelKey, modelLabel: route.label,
  });

  const result = newResult();
  const routingNote = route.auto && route.auto.tier === 'light' ? router.escalateNote(route.auto.light) : '';
  let prompt = buildPrompt({ item, thread, engine, cfg, secretsDir: paths.secrets, routingNote, workspace });

  // Resolved once per run, not once per turn: a resume is the same binary, and
  // re-running the filesystem probes on every retry would only add ways for a
  // mid-run reinstall to change the answer underneath us.
  //
  // A failure here is reported as a normal run failure rather than thrown. The
  // phone is waiting on this message, and "the agent cannot be found, here is
  // why" is an answer it can act on - an unhandled rejection is not.
  const resolved = resolveCommand(engine.command);

  const sendActivity = activitySender((body) => client.tryPost('/api/run/activity', { runId, engine: engineName, ...body }));

  const runWith = async (sessionId) => {
    if (!resolved.command) {
      result.exitCode = -1;
      result.stderr = [
        `[halyard] cannot run engine "${engineName}": ${resolved.problem}`,
        resolved.hint ? `[halyard] ${resolved.hint}` : '',
      ].filter(Boolean).join('\n');
      return result;
    }
    const env = hookEnv({ cfg, paths, client });
    const args = buildArgs(engine.args, {
      workspace,
      secrets: paths.secrets,
      permissionMode: cfg.permissionMode,
      model: (engine.modelMap && engine.modelMap[modelKey]) || modelKey || '',
      session: sessionId || '',
      ...permissionPromptArgs({ cfg, engine, paths, env }),
    });
    log.info(`run ${runId}: ${resolved.command} ${args.join(' ')}`, { thread: thread.name, engine: engineName });
    return runAgent({
      command: resolved.command,
      args,
      cwd: workspace,
      prompt,
      parse: parserFor(engine.stream),
      result,
      postExitTimeoutMs: cfg.postExitTimeoutMs,
      runTimeoutMs: cfg.runTimeoutMs,
      env,
      log,
      onActivity: sendActivity,
      isKillRequested: async () => {
        const r = await client.tryGet('/api/run/kill');
        return !!(r && r.killRequested);
      },
    });
  };

  const headBefore = cfg.diff && cfg.diff.enabled
    ? ((await gitOut(['rev-parse', 'HEAD'], workspace, { timeoutMs: 5000 })) || '').trim() || null
    : null;

  await runWith(thread.session);

  // A session id whose history no longer exists fails the entire run rather
  // than starting fresh, and the phone can do nothing useful with that report.
  // Detect exactly it, drop the id, and retake the turn as a new session.
  if (
    result.exitCode !== 0 &&
    engine.staleSessionError &&
    String(result.stderr || '').includes(engine.staleSessionError)
  ) {
    log.warn(`session ${thread.session} is gone; retaking the turn fresh`);
    threads.clearSession(paths, thread.name);
    Object.assign(result, newResult());
    await runWith('');
  }

  // Auto escalation: the light turn answered only "ESCALATE: <reason>", so the
  // heavy model retakes the same turn, resuming the session the light one just
  // wrote so it sees the original message and everything already looked at.
  // Costs add up, so the footer and the ledger show what the message really cost.
  const escalated = route.auto && route.auto.tier === 'light' && !result.killed && !result.timedOut && result.exitCode === 0
    ? router.escalation(result.reply) : null;
  if (escalated) {
    const first = { ...result };
    log.info(`run ${runId}: ${route.auto.light} handed up to ${route.auto.heavy} (${escalated})`);
    modelKey = route.auto.heavy;
    client.tryPost('/api/run/activity', {
      runId, engine: engineName, activity: `${route.auto.light} handed this to ${route.auto.heavy}: ${escalated}`, modelLabel: `${modelKey} (auto)`,
    });
    const resumeFrom = first.sessionId || thread.session || '';
    if (first.sessionId) {
      prompt = `The lighter model handed this turn up to you: ${escalated}. Take over now and handle the phone's message from the previous turn in full - the instructions in that turn still apply.`;
    } else {
      prompt = buildPrompt({ item, thread, engine, cfg, secretsDir: paths.secrets, workspace });
    }
    Object.assign(result, newResult());
    await runWith(resumeFrom);
    for (const k of ['costUsd', 'durationMs', 'numTurns']) {
      if (first[k] != null && result[k] != null) result[k] += first[k];
    }
    result.notes = [`Model: auto - ${route.auto.light} handed up to ${route.auto.heavy} (${escalated})`];
  } else if (route.auto) {
    result.notes = [`Model: auto - ${modelKey} (${route.auto.reason})`];
  }

  if (result.sessionId) threads.writeSession(paths, thread.name, result.sessionId);

  // Long threads. Clear first: at or over the clear limit the session is dropped
  // anyway (the handover is kept), so there is nothing to shrink. Never fails the
  // reply - the worst case is a note in the footer.
  if (result.sessionId && !result.killed && !result.timedOut) {
    const note = longThread({ cfg, paths, threadName: thread.name, result, log, workspace });
    if (note) result.notes = (result.notes || []).concat(note);
  }

  if (result.filesChanged.length && !result.killed && !result.timedOut) {
    const diffNote = await writeDiff({ cfg, paths, runId, thread: thread.name, headBefore, workspace });
    if (diffNote) result.notes = (result.notes || []).concat(diffNote);
  }

  if (result.killed) throw new Error('run cancelled from the phone');
  if (result.timedOut) throw new Error(`run exceeded its ${Math.round(cfg.runTimeoutMs / 60000)} minute budget and was stopped`);

  const reroute = decideReroute({ item, cfg, engineName, result });
  if (reroute) {
    log.warn(`rerouting ${item.id} from ${engineName} to ${reroute.to}: ${reroute.reason}`);
    // Front of the queue and marked `rerouted`, so the loop's own
    // while-consumed-a-message tick immediately picks it back up on the other
    // engine, and neither engine can bounce it a second time.
    // A throwing post, not tryPost: the message has already been irrevocably
    // popped, so if THIS re-queue fails there is no other record of it left
    // anywhere. Letting the failure propagate sends it through the normal
    // catch in runOnce below, which knows how to fail a message safely
    // (lastFailed + a phone-visible retry) - swallowing it here would be
    // silent, permanent loss with no way back.
    await client.post('/api/inbox', {
      message: item.message, thread: thread.name, engine: reroute.to, model: item.model || '', front: true, rerouted: true,
    });
    await client.tryPost('/api/notify', {
      message: `Rerouted to ${reroute.to}: ${reroute.reason}. Retrying now.`, thread: thread.name, engine: engineName,
    });
    return { runId, engine: engineName, rerouted: true };
  }

  if (!result.reply) {
    const tail = String(result.stderr || '').trim().split('\n').slice(-3).join(' ');
    throw new Error(`the agent exited ${result.exitCode} without producing a reply${tail ? ` (${tail})` : ''}`);
  }

  const { body, handover } = splitHandover(result.reply);

  // A reply that was nothing but its HANDOVER line leaves an empty body, and
  // /api/notify refuses an empty message - so without a placeholder the phone
  // would get no reply at all for a run that succeeded.
  const message = (body || '(the agent finished without any reply text)') + changeFooter(result);
  try {
    // NOT tryPost. This is the only copy of the reply, and invariant 2 says a
    // popped message must produce one: a swallowed failure here was the run
    // succeeding, the cost being spent, and the phone never hearing back.
    await postWithRetry(client, '/api/notify', {
      message,
      thread: thread.name,
      engine: engineName,
      prompt: item.message,
      model: modelKey || item.model || '',
      costUsd: result.costUsd,
      durationMs: result.durationMs,
      numTurns: result.numTurns,
      runId,
    });
  } catch (e) {
    // Logged in full so the answer is recoverable from halyard.log even though
    // the phone never got it, then thrown so runOnce reports the failure and
    // leaves the message retryable.
    log.error(`reply for ${item.id} could not be delivered; its text follows`, { thread: thread.name, reply: message });
    throw new Error(`the run finished but its reply could not be delivered (${e.message})`);
  }

  // Written only once the reply has landed. An undelivered turn is retried
  // from the phone, and the retry should start from the context the phone
  // last saw, not from a summary of an answer it never received.
  if (handover !== null) threads.writeHandover(paths, thread.name, handover);
  return { runId, engine: engineName };
}

// The long-thread tiers, after a run that has a session. Returns a footer note
// or null. [shrink] is injectable so the tests need no real CLI transcript.
function longThread({ cfg, paths, threadName, result, log, workspace, shrink = prunemod.shrinkSession }) {
  const c = cfg.context || {};
  const tokens = Number(result.contextTokens) || 0;
  if (!tokens) return null;
  const clearAt = Number(c.clearAtTokens) || 0;
  const shrinkAt = Number(c.shrinkAtTokens) || 0;
  // Same as the phone's "Clear context" except the handover is kept, so the
  // thread carries on from its summary instead of from nothing. Only the session
  // is dropped - that is the part that grows.
  if (clearAt > 0 && tokens >= clearAt) {
    threads.clearSession(paths, threadName);
    return `Context auto-cleared (over ${Math.round(clearAt / 1000)}k) - the next message starts fresh from the handover summary.`;
  }
  // Below the shrink threshold it is not worth it: the shrink changes the session
  // id, so the next turn misses the prompt cache, and cutting old tool output
  // loses detail a later turn may want.
  if (!(shrinkAt > 0 && tokens >= shrinkAt)) return null;
  try {
    const minPercent = Number.isFinite(Number(c.shrinkMinPercent)) ? Number(c.shrinkMinPercent) : 15;
    const r = shrink(result.sessionId, workspace || cfg.workspace, { minPercent });
    if (r.applied) {
      threads.writeSession(paths, threadName, r.newSessionId);
      log.info(`thread ${threadName}: transcript shrunk ${Math.round(r.savedPercent)}% into ${r.newSessionId} (was ${result.sessionId})`);
      return `Transcript auto-shrunk ${Math.round(r.savedPercent)}% (context was over ${Math.round(shrinkAt / 1000)}k)`;
    }
    // Not worth it this time is not news; anything else is.
    return /^would save only/.test(r.note || '') ? null : `Auto-shrink skipped: ${r.note}`;
  } catch (e) {
    return `Auto-shrink failed: ${e.message}`;
  }
}

// The usage guard. Decides BEFORE the pop, because pop is destructive: a guard
// that popped first could only drop the message or run it anyway. Fails open -
// usage unreadable, an error, no gauges, all mean "go ahead". Returns true when
// the due message should stay queued this tick.
async function usageHeld(ctx) {
  const { cfg, client, paths, log } = ctx;
  const g = cfg.usageGuard || {};
  const max = Number(g.maxPercent) || 0;
  if (max <= 0) return false;
  const peek = await client.tryPost('/api/inbox/peek');
  const item = peek && peek.item;
  if (!item) return false;
  const engine = cfg.engines[item.engine] || cfg.engines[cfg.defaultEngine];
  // The gauges are Anthropic's; another engine does not draw on them.
  if (!engine || engine.stream !== 'claude-json') return false;
  const usage = await client.tryGet('/api/usage');
  const over = usagemod.blockingGauge(usage, max);
  const marker = path.join(paths.root, '.usage-hold');
  if (!over) {
    // Not blocked: clear any prior hold so the next one is announced at once.
    try { fs.unlinkSync(marker); } catch (e) { /* none */ }
    return false;
  }
  await client.tryPost('/api/inbox/hold', { id: item.id, gauge: over.name, percent: over.percent, resetsAt: over.resetsAt });
  // At most one announcement per window, so a multi-hour hold does not evict
  // every real reply from the phone's ring.
  const every = Number(g.announceEveryMs) || 30 * 60 * 1000;
  let last = 0;
  try { last = fs.statSync(marker).mtimeMs; } catch (e) { /* first */ }
  if (Date.now() - last >= every) {
    const reset = over.resetsAt ? ` It resets at ${over.resetsAt}.` : '';
    await client.tryPost('/api/notify', {
      message: `[halyard] usage guard: ${over.name} is at ${Math.round(over.percent)}% (limit ${max}%), so your message is staying queued instead of running.${reset} It starts by itself once usage drops.`,
      thread: item.thread || threads.DEFAULT_THREAD,
      engine: item.engine || '',
    });
    try { fs.writeFileSync(marker, String(Date.now())); } catch (e) { /* best effort */ }
    log.info(`usage guard holding ${item.id}: ${over.name} at ${over.percent}%`);
  }
  return true;
}

async function spendHeld(ctx) {
  const { cfg, client, paths, log } = ctx;
  const g = cfg.spendGuard || {};
  const cap = Number(g.dailyUsd) || 0;
  if (cap <= 0) return false;
  const peek = await client.tryPost('/api/inbox/peek');
  const item = peek && peek.item;
  if (!item) return false;
  const spend = await client.tryGet('/api/spend?days=1');
  const today = spend && Number.isFinite(spend.todayUsd) ? spend.todayUsd : null;
  const marker = path.join(paths.root, '.spend-hold');
  if (today === null || today < cap) {
    try { fs.unlinkSync(marker); } catch (e) { /* none */ }
    return false;
  }
  const midnight = new Date();
  midnight.setHours(24, 0, 0, 0);
  await client.tryPost('/api/inbox/hold', {
    id: item.id, gauge: 'daily spend', percent: Math.round((100 * today) / cap), resetsAt: midnight.toISOString(),
  });
  const every = Number(g.announceEveryMs) || 30 * 60 * 1000;
  let last = 0;
  try { last = fs.statSync(marker).mtimeMs; } catch (e) { /* first */ }
  if (Date.now() - last >= every) {
    await client.tryPost('/api/notify', {
      message: `[halyard] spend guard: today has cost $${today.toFixed(2)} (limit $${cap.toFixed(2)}), so your message is staying queued instead of running. It starts by itself after midnight, or raise spendGuard.dailyUsd.`,
      thread: item.thread || threads.DEFAULT_THREAD,
      engine: item.engine || '',
    });
    try { fs.writeFileSync(marker, String(Date.now())); } catch (e) { /* best effort */ }
    log.info(`spend guard holding ${item.id}: $${today.toFixed(2)} of $${cap.toFixed(2)}`);
  }
  return true;
}

// Retries a throwing post with a short backoff. Sized to ride out a server
// restart (routine here - the agent is allowed to restart it), not an outage.
// A 4xx is the server refusing this body, and sending it again changes nothing.
async function postWithRetry(client, p, body, { attempts = 4, delayMs = 1000 } = {}) {
  for (let i = 1; ; i++) {
    try {
      return await client.post(p, body);
    } catch (e) {
      if (i >= attempts || (e.status >= 400 && e.status < 500)) throw e;
      await new Promise((resolve) => setTimeout(resolve, delayMs * 2 ** (i - 1)));
    }
  }
}

// Pops at most one message and runs it. Returns true if it consumed one, which
// is what makes the self-retrigger chain below terminate.
async function runOnce(ctx) {
  const { cfg, client, paths, log } = ctx;
  // The age limit has to cover the longest LEGITIMATE hold, not one run: a
  // stale session retakes the turn, so one message can be two full runs, each
  // with its post-exit drain, plus the reply's delivery retries. Sized to
  // runTimeoutMs alone, a second watcher (a `halyard watch` timer) reaped the
  // lock from under a live retake and popped another message beside it.
  const maxAgeMs = 2 * (cfg.runTimeoutMs + cfg.postExitTimeoutMs) + 60 * 1000;
  const release = lock.acquire(paths.lockDir, 'watch', { maxAgeMs, log });
  if (!release) {
    log.debug('another run holds the lock; skipping this tick');
    return false;
  }

  let item = null;
  try {
    // Inside the try so the finally still releases the lock. Not consuming here
    // is what ends the loop's re-trigger chain while usage stays high.
    if (await usageHeld(ctx) || await spendHeld(ctx)) return false;
    const popped = await client.post('/api/inbox/pop');
    item = popped && popped.item;
    if (!item) return false;

    log.info(`popped message ${item.id}`, { thread: item.thread, engine: item.engine });
    await processOne(ctx, item);
    return true;
  } catch (e) {
    log.error(`run failed: ${e.message}`);
    if (item) {
      // Invariant 2. The message is already gone from the queue, so the phone
      // is waiting on this run and nothing else will answer it. Report the
      // failure AND hand the message back so one tap re-queues it.
      await client.tryPost('/api/run/failed', {
        reason: e.message,
        item,
      });
    }
    return !!item;
  } finally {
    await client.tryPost('/api/run/end', {});
    release();
  }
}

// The loop. Two triggers, for two different failure modes: the interval catches
// anything the nudge missed (server restarted, watcher was busy), and the nudge
// makes a message start now rather than up to one interval later.
function startLoop(ctx) {
  const { cfg, log } = ctx;
  let running = false;
  let stopped = false;

  const tick = async () => {
    if (running || stopped) return;
    running = true;
    try {
      // Keep going while there is work. Gated on having actually CONSUMED a
      // message, never on the queue being non-empty: a loop that re-runs
      // because the queue is non-empty, in a state where it cannot pop (a held
      // lock, a paused engine), is an unbounded spawn loop. Every iteration
      // here has removed one message, which is what makes it terminate.
      let consumed = true;
      let guard = 0;
      while (consumed && !stopped && guard++ < 100) {
        consumed = await runOnce(ctx);
      }
    } catch (e) {
      log.error(`watcher tick failed: ${e.message}`);
    } finally {
      running = false;
    }
  };

  const timer = setInterval(tick, cfg.watchIntervalMs);
  if (timer.unref) timer.unref();
  setTimeout(tick, 500).unref?.();

  return {
    nudge: tick,
    stop: () => { stopped = true; clearInterval(timer); },
  };
}

module.exports = {
  runOnce, startLoop, runAgent, buildArgs, buildPrompt, splitHandover, changeFooter, decideReroute, CAPACITY_OR_AUTH,
  hookEnv, permissionPromptArgs, postWithRetry, longThread, usageHeld, spendHeld, activitySender, gitOut, diffHtml, writeDiff,
};
