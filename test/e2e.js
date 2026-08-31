// End-to-end: a real server, a real watcher, and a FAKE agent CLI.
//
// The smoke suite tests the server's routes and the parsers in isolation. This
// tests the part that only exists once they are wired together: queue a
// message, have the watcher pop it, spawn a process, read a stream-json
// conversation off its stdout, and land a reply the phone can see.
//
// The fake agent is a node script that speaks Claude Code's stream-json dialect
// and, in one mode, deliberately misbehaves - it spawns a grandchild that holds
// the pipes open for a minute after it exits. That is the hang this whole
// design is shaped around, and a test that never reproduces it is a test that
// would pass on a build where it comes back.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const pathsmod = require('../src/paths');
const configmod = require('../src/config');
const { createServer } = require('../src/server');
const { createLogger } = require('../src/log');
const { createClient } = require('../src/client');
const watcher = require('../src/watcher');
const engines = require('../src/engines');

const results = [];
function record(name, e) {
  results.push(!e);
  console.log(e ? `  FAIL  ${name}\n        ${e.stack || e.message}` : `  ok    ${name}`);
}

// A stand-in agent. Reads the prompt on stdin (which is itself part of what is
// being tested - an argv prompt would arrive truncated), then emits a plausible
// stream-json conversation.
const FAKE_AGENT = `
const chunks = [];
process.stdin.on('data', (c) => chunks.push(c));
process.stdin.on('end', () => {
  const prompt = Buffer.concat(chunks).toString('utf8');
  const emit = (o) => process.stdout.write(JSON.stringify(o) + '\\n');
  emit({ type: 'system', session_id: 'sess-123' });
  emit({ type: 'assistant', message: { content: [{ type: 'text', text: 'Let me look at that.' }] } });
  emit({ type: 'assistant', message: { content: [{ type: 'tool_use', name: 'Read', input: { file_path: '/tmp/a.js' } }] } });
  emit({ type: 'assistant', message: { content: [{ type: 'tool_use', name: 'Edit', input: { file_path: '/tmp/a.js' } }] } });
  // The whole prompt has to be here, quotes and all, or the argv bug is back.
  const got = prompt.includes('SENTINEL "quoted phrase" END') ? 'prompt-intact' : 'PROMPT-TRUNCATED';
  emit({
    type: 'result',
    session_id: 'sess-123',
    result: got + String.fromCharCode(10) + 'HANDOVER: carried this over',
    total_cost_usd: 0.0123, duration_ms: 2500, num_turns: 3,
  });
  if (process.env.FAKE_HANG === '1') {
    // A grandchild that inherits stdout and stderr and holds them open long
    // after this process is gone. Without a bound on the post-exit read, the
    // watcher waits here forever while holding the run lock.
    require('child_process').spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], { stdio: ['ignore', 'inherit', 'inherit'] }).unref();
  }
  process.exit(0);
});
`;

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'halyard-e2e-'));
  const paths = pathsmod.ensure(pathsmod.layout(dir));
  const agentFile = path.join(dir, 'fake-agent.js');
  fs.writeFileSync(agentFile, FAKE_AGENT);

  const cfg = configmod.load({
    file: null,
    env: {},
    cli: {
      port: 0,
      workspace: dir,
      defaultEngine: 'fake',
      // An engine is DATA: this is the whole of "adding support for a new CLI".
      engines: {
        fake: {
          label: 'Fake agent',
          command: process.execPath,
          args: [agentFile, '--model', '{{model}}', '--resume', '{{session}}', '--add-dir', '{{workspace}}'],
          stream: 'claude-json',
          modelMap: { fast: 'fake-fast-1' },
          supportsRelayHook: false,
        },
      },
      // Short, so the hang test does not take 20 seconds to prove its point.
      postExitTimeoutMs: 2000,
      runTimeoutMs: 20000,
      watchIntervalMs: 999999,
    },
  });

  const log = createLogger(path.join(dir, 'e2e.log'), 'error');
  const token = 'e2e-token';
  let subs = [];
  const ctx = {
    cfg, paths, log, token, warnings: [],
    pushKeys: () => null, pushSubs: () => subs,
    addPushSub: (s) => { subs = subs.concat(s); }, removePushSub: () => {},
    nudge: () => {},
  };
  const app = createServer(ctx);
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  cfg.port = app.server.address().port;
  const client = createClient(cfg, token);

  try {
    // --- the happy path --------------------------------------------------
    await client.post('/api/inbox', { message: 'do the thing SENTINEL "quoted phrase" END', thread: 'work', model: 'fast' });
    const consumed = await watcher.runOnce({ cfg, paths, log, client });

    try {
      assert.strictEqual(consumed, true, 'the watcher should have consumed one message');
      const notes = (await client.get('/api/notifications')).items;
      assert.strictEqual(notes.length, 1, `expected one reply, got ${notes.length}`);
      record('a queued message runs and produces a reply', null);
    } catch (e) { record('a queued message runs and produces a reply', e); }

    const note = (await client.get('/api/notifications')).items[0];

    try {
      // The single most expensive bug this project has: a prompt passed as argv
      // gets split at its first quote, the model answers a truncated question,
      // and nothing reports an error.
      assert.ok(note.message.startsWith('prompt-intact'), `prompt did not survive: ${note.message.slice(0, 80)}`);
      record('the prompt crosses to the agent intact, quotes and all', null);
    } catch (e) { record('the prompt crosses to the agent intact, quotes and all', e); }

    try {
      assert.ok(!note.message.includes('HANDOVER:'), 'the handover line must be stripped from what the phone sees');
      const h = await client.get('/api/handover?thread=work');
      assert.strictEqual(h.text, 'carried this over');
      assert.strictEqual(h.exists, true);
      record('the handover is stripped from the reply and stored on the thread', null);
    } catch (e) { record('the handover is stripped from the reply and stored on the thread', e); }

    try {
      assert.strictEqual(fs.readFileSync(path.join(paths.threads, 'work.session'), 'utf8'), 'sess-123');
      record('the session id is recorded so the next turn resumes', null);
    } catch (e) { record('the session id is recorded so the next turn resumes', e); }

    try {
      assert.strictEqual(note.costUsd, 0.0123);
      assert.strictEqual(note.model, 'fast');
      assert.strictEqual(note.thread, 'work');
      assert.ok(note.message.includes('Edited 1 file'), 'the change footer should name the edit');
      assert.ok(note.message.includes('$0.0123'));
      record('the reply carries the metadata the ledger needs', null);
    } catch (e) { record('the reply carries the metadata the ledger needs', e); }

    try {
      const ledger = fs.readFileSync(paths.runs, 'utf8').trim().split('\n').map(JSON.parse);
      assert.strictEqual(ledger.length, 1);
      assert.strictEqual(ledger[0].thread, 'work');
      record('the run lands in the spend ledger', null);
    } catch (e) { record('the run lands in the spend ledger', e); }

    try {
      assert.strictEqual((await client.get('/api/health')).activeRun, null, 'the run must be cleared when it ends');
      record('the active run is cleared afterwards', null);
    } catch (e) { record('the active run is cleared afterwards', e); }

    // --- the grandchild that holds the pipes open -------------------------
    process.env.FAKE_HANG = '1';
    await client.post('/api/inbox', { message: 'hang test SENTINEL "quoted phrase" END', thread: 'work' });
    const started = Date.now();
    await watcher.runOnce({ cfg, paths, log, client });
    const elapsed = Date.now() - started;
    delete process.env.FAKE_HANG;

    try {
      // The grandchild lives for 60s. Returning at all is the assertion; the
      // bound is 2s here, so anything under ~15s proves it fired.
      assert.ok(elapsed < 15000, `run took ${elapsed}ms - the post-exit bound did not fire`);
      const notes = (await client.get('/api/notifications')).items;
      assert.strictEqual(notes.length, 2, 'the second run must still deliver a reply');
      assert.ok(notes[0].message.startsWith('prompt-intact'));
      record('a lingering grandchild cannot wedge the run', null);
    } catch (e) { record('a lingering grandchild cannot wedge the run', e); }

    try {
      // The lock is released in a finally, so the next run can start. A held
      // lock is indistinguishable from a dead bridge from the phone's side.
      const held = require('../src/lock').inspect(paths.lockDir, 'watch');
      assert.strictEqual(held, null, 'the run lock must be released even after the bounded escape');
      record('the run lock is released after a bounded escape', null);
    } catch (e) { record('the run lock is released after a bounded escape', e); }

    // --- a failing agent still answers the phone --------------------------
    const badFile = path.join(dir, 'bad-agent.js');
    fs.writeFileSync(badFile, 'process.stdin.resume(); process.stdin.on("end", () => { console.error("boom"); process.exit(3); });');
    cfg.engines.fake.args = [badFile];
    await client.post('/api/inbox', { message: 'this will fail', thread: 'work' });
    await watcher.runOnce({ cfg, paths, log, client });

    try {
      const health = await client.get('/api/health');
      // The pop is destructive with no re-queue, so a run that consumes a
      // message without answering it MUST hand it back for one-tap retry.
      assert.ok(health.lastFailed, 'a failed run must leave the message retryable');
      assert.strictEqual(health.lastFailed.message, 'this will fail');
      const notes = (await client.get('/api/notifications')).items;
      assert.ok(notes[0].message.startsWith('[halyard]'), 'the phone must be told the run failed');
      record('a failing agent still produces a phone-visible reply and a retry', null);
    } catch (e) { record('a failing agent still produces a phone-visible reply and a retry', e); }

    try {
      await client.post('/api/inbox/retry');
      const item = (await client.post('/api/inbox/pop')).item;
      assert.strictEqual(item.message, 'this will fail');
      record('retry puts the eaten message back at the front', null);
    } catch (e) { record('retry puts the eaten message back at the front', e); }
  } finally {
    await app.close();
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* windows holds files briefly */ }
  }

  const failed = results.filter((r) => !r).length;
  console.log(failed ? `\n  ${results.length - failed} passed, ${failed} FAILED\n` : `\n  ${results.length} checks passed\n`);
  if (failed) process.exitCode = 1;
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
