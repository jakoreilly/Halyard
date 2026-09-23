# Pruning a thread's transcript

How `prune-session.js` works, why each decision went the way it did, and what would
have to change to lift it into another bridge. Written to be portable: nothing below
depends on this machine, and the only host-specific thing in the whole design is
where the CLI keeps its transcripts.

## The problem

A bridge thread resumes a real CLI session (`--resume <id>`), so every turn reloads
the entire transcript - including the output of every `git status`, every build log
and every file read. The conversation is a rounding error inside it. When the window
fills, compaction discards the lot, conversation included.

Measured on a live `main` thread (2026-09-23, 842 lines, 2.30 MB):

| part | share |
|---|---|
| `tool_result` lines (with their duplicate, below) | 31.1% |
| `tool_use` lines | 24.2% |
| `instructions` attachments | 10.4% |
| `thinking` | 10.1% |
| whole files echoed back after an edit | 4.0% |
| token-count reminders (142 of them) | 3.7% |
| **assistant prose - the actual conversation** | **~2%** |

So there is a lot to remove before anything worth keeping is at risk. Pruning tool
output alone took that transcript down 21.4%; also dropping bookkeeping attachments
took it down 44.9%.

## The one thing that is easy to get wrong

**Tool output is stored twice.** There is the `tool_result` block inside
`message.content`, and a `toolUseResult` field at the top level of the same line.
On the measured transcript the top-level copy was **441 KB against the blocks' 177
KB** - so pruning the blocks alone removes about a quarter of the weight while the
code looks, and tests, entirely correct.

```js
// both, every time
for (const block of obj.message.content) {
  if (block.type === 'tool_result') block.content = head + marker;
}
if (obj.toolUseResult !== undefined) obj.toolUseResult = { pruned: true, originalBytes };
```

## Rules the implementation holds to

- **Shrink blocks, never delete them.** An assistant `tool_use` whose
  `tool_result` has gone - or a result with no call - is a malformed conversation,
  and the API rejects the *whole request*, not the bad pair. Every prune leaves the
  block and its `tool_use_id` exactly where they were and only replaces the text.
- **Keep a head, not nothing.** The first ~300 characters survive, so the model can
  still tell a command that worked from one that failed and is worth retrying. A
  bare `[pruned]` turns a known result into an unknown one, which is worse than
  either keeping or forgetting it.
- **Never write over the original.** Output goes to a **new session id**; the thread
  is repointed only with `--point`, and the old id is printed so putting it back is
  one line. A bad prune then costs nothing at all.
- **Dry run by default.** `--apply` is the only thing that writes.
- **Refuse a live transcript.** If the file was written in the last 120 seconds a
  run is probably appending to it, and copying mid-append gives a truncated last
  line. `--force` overrides.
- **Leave unparseable lines exactly as they are.** A line this script cannot read is
  far more likely to be a format it has not seen than something worth deleting.
- **Check the pairing before writing.** `verify()` re-reads the output and fails the
  whole run if any `tool_result` lost its `tool_use`. One dangling *call* at the end
  is normal - that is the turn in progress - so only an orphaned result, or more
  than one unanswered call, is treated as a fault.

## Attachments are opt-in, deliberately

`--attachments` drops whole lines of harness bookkeeping: token-count reminders,
prompt snapshots, skill listings, re-read instruction files, and files echoed back
after an edit. It nearly doubles the saving. It is not the default because unlike a
`tool_result` - which has a documented shape in the API - these are whole lines whose
reconstruction is the CLI's business, and the format is undocumented. Prove it on a
thread you would not miss first.

## What was not built, and why

- **A local model deciding what to keep.** Tempting, and wrong for a first pass: a
  build log, a `git status`, a file read of something edited two steps later are all
  droppable by rule. A classifier that is two-thirds right is a bad trade when being
  wrong deletes something you needed. Rules first; measure; only then consider a
  model for the leftovers.
- **Summarising the pruned output.** That needs generated text, which means a paid
  call per prune, and the summary would be of material the head already covers.
- **Hooking the CLI's own compaction.** There is no hook for it. Rewriting the
  transcript is the only lever a bridge actually holds.

## Porting it

Three things are host-specific and all three are in one place:

1. **Where transcripts live.** Here: `~/.claude/projects/<cwd-with-separators-as-dashes>/<session-id>.jsonl`
   (`C:\Users\me\Code\bridge` → `C--Users-me-Code-bridge`). `projectDir()` is the
   only function that knows this.
2. **Where a thread's session id is kept.** Here, `session.txt` for the default
   thread and `threads/<slug>.session` for the rest - `threadSessionFile()`, which
   applies the same `[a-z0-9-]` allow-list the server uses, because the string
   becomes a filename.
3. **Which engine's transcript it is.** This understands the Claude Code shape only.
   Another CLI storing its history differently needs its own reader; the rules above
   (shrink don't delete, copy-on-write, verify pairing) carry over unchanged.

Everything else - `prune()`, `pruneLine()`, `verify()` - is pure and testable
without a session file, which is how the suite covers it.

## Proving it

Unit tests cover the traps: the id surviving, the duplicate being pruned, prose and
thinking untouched, short output left alone, an unparseable line passed through, and
`verify()` catching an orphaned result.

But the only proof that matters is a resume. Prune a small throwaway session, then:

```
claude.exe --resume <new-id> --model <cheap-model> -p "name the topic of this conversation"
```

If it answers from the history, the pruned transcript is valid. Done here against
CLI **2.1.278** on 2026-09-23: 15% lighter, and the model still named the topic.
Re-run this after any CLI update - the format is undocumented and can move.
