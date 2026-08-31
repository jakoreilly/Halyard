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

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const { parserFor, newResult } = require('./engines');
const lock = require('./lock');
const threads = require('./threads');

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
      try { child.kill('SIGKILL'); } catch (e) { /* already dead */ }
      // Do not resolve here. The exit handler runs next and applies the same
      // bounded drain, so a reply that had already been emitted is still read.
    }, runTimeoutMs);

    killPoll = setInterval(async () => {
      try {
        if (await isKillRequested()) {
          result.killed = true;
          child.kill('SIGKILL');
        }
      } catch (e) {
        // A health check failing is not a reason to kill a working run.
      }
    }, 2000);
  });
}

// ---------------------------------------------------------------------------
// Prompt assembly

function buildPrompt({ item, thread, engine, cfg }) {
  const parts = [];
  parts.push(
    'You are answering a message sent from a phone through Halyard, a local bridge to this machine.',
    '',
    `Working directory: ${cfg.workspace}`,
    `Permission mode: ${cfg.permissionMode}`,
    cfg.relay && cfg.relay.enabled && engine.supportsRelayHook
      ? 'Mutating git commands, recursive deletes and outbound network calls are relayed to the phone for an approve/deny tap before they run. Use them normally; expect one pause.'
      : 'There is no approve/deny relay on this engine. Be conservative with anything destructive or outbound.',
    '',
    'Reply concisely - the answer is read on a phone screen. Prefer doing the work and reporting what you did over asking whether you should.',
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
    return bits.length ? `\n\n---\n${bits.join(' · ')}` : '';
  } catch (e) {
    return '';
  }
}

// ---------------------------------------------------------------------------
// One turn

async function processOne(ctx, item) {
  const { cfg, client, paths, log } = ctx;
  const engineName = cfg.engines[item.engine] ? item.engine : cfg.defaultEngine;
  const engine = cfg.engines[engineName];
  const thread = threads.read(paths, item.thread);
  const runId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  await client.tryPost('/api/run/start', {
    runId, engine: engineName, thread: thread.name, message: item.message, model: item.model || '',
  });

  const result = newResult();
  const prompt = buildPrompt({ item, thread, engine, cfg });

  const runWith = async (sessionId) => {
    const args = buildArgs(engine.args, {
      workspace: cfg.workspace,
      permissionMode: cfg.permissionMode,
      model: (engine.modelMap && engine.modelMap[item.model]) || item.model || '',
      session: sessionId || '',
    });
    log.info(`run ${runId}: ${engine.command} ${args.join(' ')}`, { thread: thread.name, engine: engineName });
    return runAgent({
      command: engine.command,
      args,
      cwd: cfg.workspace,
      prompt,
      parse: parserFor(engine.stream),
      result,
      postExitTimeoutMs: cfg.postExitTimeoutMs,
      runTimeoutMs: cfg.runTimeoutMs,
      log,
      onActivity: ({ activity, draft }) => {
        // Fire and forget. An activity update that fails to post costs one
        // line on a status panel; awaiting it would let a slow round trip
        // throttle the parse loop.
        client.tryPost('/api/run/activity', { runId, engine: engineName, activity, draft });
      },
      isKillRequested: async () => {
        const health = await client.tryGet('/api/health');
        return !!(health && health.activeRun && health.activeRun.killRequested);
      },
    });
  };

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

  if (result.sessionId) threads.writeSession(paths, thread.name, result.sessionId);

  if (result.killed) throw new Error('run cancelled from the phone');
  if (result.timedOut) throw new Error(`run exceeded its ${Math.round(cfg.runTimeoutMs / 60000)} minute budget and was stopped`);
  if (!result.reply) {
    const tail = String(result.stderr || '').trim().split('\n').slice(-3).join(' ');
    throw new Error(`the agent exited ${result.exitCode} without producing a reply${tail ? ` (${tail})` : ''}`);
  }

  const { body, handover } = splitHandover(result.reply);
  if (handover !== null) threads.writeHandover(paths, thread.name, handover);

  await client.tryPost('/api/notify', {
    message: body + changeFooter(result),
    thread: thread.name,
    engine: engineName,
    prompt: item.message,
    model: item.model || '',
    costUsd: result.costUsd,
    durationMs: result.durationMs,
    numTurns: result.numTurns,
  });
  return { runId, engine: engineName };
}

// Pops at most one message and runs it. Returns true if it consumed one, which
// is what makes the self-retrigger chain below terminate.
async function runOnce(ctx) {
  const { cfg, client, paths, log } = ctx;
  const release = lock.acquire(paths.lockDir, 'watch', { maxAgeMs: cfg.runTimeoutMs, log });
  if (!release) {
    log.debug('another run holds the lock; skipping this tick');
    return false;
  }

  let item = null;
  try {
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

module.exports = { runOnce, startLoop, runAgent, buildArgs, buildPrompt, splitHandover, changeFooter };
