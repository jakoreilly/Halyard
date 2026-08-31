# Engines

An engine is a CLI plus a way of reading what it says while it works. The CLI half is pure
configuration. The reading half is one of three built-in dialects, or a small function you
add.

Adding support for an agent should not require a pull request, and for most agents it does
not.

## The shape

```jsonc
"engines": {
  "myagent": {
    "label": "My Agent",              // shown in the phone's engine picker
    "command": "myagent",             // resolved on PATH, or an absolute path
    "args": ["--print", "--model", "{{model}}"],
    "stream": "text",                 // claude-json | copilot-json | text
    "modelMap": { "fast": "myagent-turbo" },
    "supportsRelayHook": false        // be honest — this is surfaced to the user
  }
}
```

User entries merge **on top of** the built-ins, so pointing the bundled `claude` engine at a
binary that is not on your PATH is one line:

```json
"engines": { "claude": { "command": "/opt/claude/bin/claude" } }
```

## Placeholders

Substituted at spawn time:

| | |
|---|---|
| `{{workspace}}` | the directory the agent may work in |
| `{{model}}` | the phone's selection, mapped through `modelMap` |
| `{{session}}` | the thread's prior session id, for resuming |
| `{{permissionMode}}` | the configured permission mode |

**An argument pair whose value resolves to empty is dropped whole.** That is what lets one
template cover "no model selected" *and* "first message in a thread, so nothing to resume":

```jsonc
["--print", "--model", "{{model}}", "--resume", "{{session}}", "--add-dir", "{{workspace}}"]
// model="", session="" →  ["--print", "--add-dir", "/home/you/code"]
```

`--model` with nothing after it is not a smaller request, it is a usage error that fails the
whole run.

## The prompt is never an argument

There is no `{{prompt}}` placeholder, and adding one would be a mistake.

The prompt is written to the agent's **stdin**. Passing a multi-paragraph prompt as argv
works right up until it contains a quote character, at which point some platforms'
native-argument re-parsing strips the quote and splits on the following whitespace. The
prompt arrives truncated, the model answers the truncated question, and **nothing anywhere
reports an error** — worse, if that turn writes a handover summary, the truncation persists
into every later turn in the thread.

Your engine must therefore read its prompt from stdin. Most already can:

```jsonc
"args": ["--message-file", "-"]     // aider
"args": ["--print"]                 // claude code (stdin is the default input)
"args": []                          // anything that just reads stdin
```

## Stream dialects

### `text`

Any CLI that reads a prompt on stdin and prints an answer on stdout. Every line is appended
to the reply. No activity line, no session resume, no cost — but it works, and it is the
right starting point.

```jsonc
{ "label": "Aider", "command": "aider", "args": ["--no-pretty", "--yes", "--message-file", "-"], "stream": "text" }
```

### `claude-json`

Claude Code's `--output-format stream-json --verbose`. Understands `system`, `assistant` and
`result` events; produces the live activity line from `tool_use` blocks, the draft answer
from `text` blocks, and takes the final reply, session id, cost, duration and turn count off
the terminal `result` event.

### `copilot-json`

GitHub Copilot CLI's `--output-format json`. Not the same shape, and the difference matters:
the final reply is the **last `assistant.message` whose `data.toolRequests` is empty**, not a
field on `result` (which carries only `sessionId`, `exitCode` and `usage`). Getting this
wrong does not error — it silently returns a mid-run tool-call turn as the answer.

## Writing a new dialect

Add a parser to `src/engines/index.js`. The contract is small and two callers depend on it:

```js
parse(line, result) -> string | null
```

- The **return value is the activity label only** — one short line, or `null`.
- Everything else is written onto `result` as a side effect: `reply`, `sessionId`,
  `lastText` (the model's verbatim prose, which becomes the draft answer), `costUsd`,
  `durationMs`, `numTurns`, `filesChanged`, `commands`.
- Assign optional fields **only when present**. `null` means "the engine did not report
  this" everywhere downstream, and a cost of `0` is a real result that must not become
  indistinguishable from a missing one. Use a presence check, never truthiness.
- Never throw on a malformed line. Agent CLIs interleave plain-text warnings and progress
  output; skipping the line is correct, ending the run is not.

Activity and draft **move independently** — Copilot emits prose on an event that produces no
activity label at all — so the run loop tracks them separately. That is why prose goes on
`result.lastText` rather than being returned.

## Session resume

If your engine can resume a conversation by id:

1. Emit the id somewhere your parser can see it, and set `result.sessionId`.
2. Put `"--resume", "{{session}}"` in `args`.

Halyard stores it per thread and passes it back on the next turn. If the id later stops
resolving, set `staleSessionError` to a distinctive substring the CLI writes to stderr in
that case — the watcher detects exactly that, drops the id, and retakes the turn as a fresh
session rather than reporting a failure your phone cannot act on.

## The relay flag

`supportsRelayHook` says whether the CLI has a pre-tool hook Halyard's approve/deny relay
can attach to. Set it honestly. It is not cosmetic:

- `halyard doctor` prints `[no pre-tool hook: relay cannot arm]`
- the phone's engine picker appends `(no relay)`
- the configuration audit warns if your **default** engine is one of them

An engine marked `true` that has no such hook is a bridge that claims a backstop it does not
have, which is worse than one that admits it has none.

## Testing yours

`test/e2e.js` registers a fake engine as pure config and drives the whole loop against it —
including a mode where the fake agent leaves a grandchild holding the pipes open. Copy that
file, point it at your CLI, and you have a real test for your engine:

```js
engines: {
  mine: { label: 'Mine', command: '/usr/bin/myagent', args: ['--stdin'], stream: 'text' }
}
```
