# Contributing

## Run it

```sh
git clone https://github.com/jakoreilly/Halyard && cd Halyard
node bin/halyard.js setup --data-dir ./dev-data
node bin/halyard.js start --data-dir ./dev-data --port 4599
```

There is no install step and no build step. `node -v` ≥ 18.17 is the whole toolchain.

```sh
npm test          # smoke + e2e
npm run check     # syntax gate, including the page's inline script
```

Both suites run against a throwaway data directory on an ephemeral port, so you can run them
while a real bridge is serving a real phone.

## The rules this project actually has

**Zero runtime dependencies.** Not asceticism — it is what makes "clone it and run it" true
on a machine you do not control, and it keeps the supply chain for a service holding a
bearer token and an agent's leash down to node itself. A PR that adds a dependency needs to
argue for it.

**Comments say *why*, and name the bug.** Most of the non-obvious code here is shaped by
something that failed silently in production. If you change one of those places, keep the
explanation and update it; if you fix a new one, write down what it was. A comment that says
what the line does is noise. A comment that says what happens if you "simplify" it is the
most valuable thing in the file.

**Tests pin silent failures, not obvious ones.** A path-traversal guard, a log allow-list, a
query default that read "absent" as zero, a service worker whose install rejected and left
last month's worker running, a push payload accepted with a 201 and never delivered. Each
has a test whose comment names the bug. New guards want the same treatment; a test for
something that would fail loudly in review is worth much less.

**Configuration is data.** If a change would make someone edit a source file to run Halyard
on their machine, it belongs in config instead. Engines especially — adding an agent CLI
should not need a pull request.

**Ship the failure mode.** Every warning `halyard doctor` prints names a real, specific
exposure in plain words. Nothing here refuses to run in a configuration its author disagrees
with; a tool that does that just gets forked.

## Things to leave alone

Each of these has a comment in the source saying why. If you are about to change one,
read that first — they all look like obvious simplifications.

| | |
|---|---|
| The prompt goes in on **stdin**, never argv | A quote in the prompt truncates it silently on some platforms |
| Every read of the agent's pipes is **bounded** | A grandchild holding stdout hangs the run forever with the lock held |
| The relay matches **eagerly**, quotes and all | `sh -c "git push --force"` is quoted and executes |
| `SHELL_URLS` in `sw.js` is **token-free**, and precaching cannot fail the install | An install that rejects never activates, and the old worker keeps control |
| `/api/logs` takes a **key**, never a path | The token file is in the same directory |
| Thread names are an **allow-list** of `[a-z0-9-]` | The string becomes a filename |
| `null` means "not reported"; `0` is a real value | A footer reading `$0.00` because a field moved is worse than one with fewer items |
| The change stream carries **counters, not data** | Health is refetched on every activity bump |

## Adding an engine

Usually zero code — see [docs/ENGINES.md](docs/ENGINES.md). If it needs a new stream dialect,
add a parser to `src/engines/index.js` and a case to `test/smoke.js`.

Set `supportsRelayHook` honestly. An engine that claims a backstop it does not have is worse
than one that admits it has none.

## Style

Match what is there. Two-space indent, semicolons, CommonJS, no transpiler. Prefer a plain
function over a class and a plain object over an abstraction; there is no DI container here
and there does not need to be one.

## Pull requests

Say what changed and why, grouped by intent rather than file by file, and call out anything
with a testing or safety consequence. If you changed something in the "leave alone" table,
lead with that.
