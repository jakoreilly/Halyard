# Configuration

Halyard is configured by one JSON file. Nothing that varies between machines lives in the
repository, which is what makes `git pull` safe and a fork useful to someone else.

## Where things live

| | |
|---|---|
| Linux | `$XDG_STATE_HOME/halyard` or `~/.local/state/halyard` |
| macOS | `~/Library/Application Support/halyard` |
| Windows | `%LOCALAPPDATA%\halyard` |

Override with `--data-dir <path>` or `HALYARD_DATA_DIR`. Two installs on one machine are two
data directories; a portable install on a USB stick is `--data-dir .`.

`halyard doctor` prints the resolved path, which is always the fastest way to answer "which
config is it actually reading?".

## Layering

Later wins:

```
built-in defaults  →  halyard.config.json  →  HALYARD_* env vars  →  CLI flags
```

A corrupt config file is **reported and skipped**, never fatal. An unreachable bridge is
worse than a bridge running on defaults, and your phone is often the only device around to
notice either way.

## Every setting

### Network

| Key | Default | Notes |
|---|---|---|
| `host` | `127.0.0.1` | Anything else prints a warning. Use a tunnel — see [REMOTE-ACCESS.md](REMOTE-ACCESS.md). |
| `port` | `4545` | |
| `publicUrl` | `""` | Your tunnel's origin, e.g. `https://desk.tail1234.ts.net`. Used in push payloads so a notification tap opens the right place. |

### Agent

| Key | Default | Notes |
|---|---|---|
| `defaultEngine` | `claude` | Must name an entry in `engines`. An unknown value falls back with a warning rather than failing to start. |
| `workspace` | cwd at setup | The single directory the agent is scoped to. **Not** your home directory by default. |
| `permissionMode` | `default` | Passed straight through. `default` means the agent's own rules apply. |
| `runTimeoutMs` | `1800000` | 30 minutes. A run that hangs holds the lock, and a held lock looks exactly like a dead bridge from the phone. |
| `postExitTimeoutMs` | `20000` | How long to keep reading the agent's pipes after it exits. See below — this one is not arbitrary. |
| `engines` | `{}` | Merged **on top of** the built-ins, so overriding just `command` does not mean restating the whole argument template. See [ENGINES.md](ENGINES.md). |

<details>
<summary><b>Why <code>postExitTimeoutMs</code> exists</b></summary>

A grandchild process that inherited the agent's stdout — a shell left behind by a tool call
— holds that pipe open after the agent itself has exited. Waiting for EOF there waits
forever, while holding the run lock, and the whole bridge is wedged until someone kills the
process by hand.

So EOF is not the only exit condition: once the agent has exited, the read gets this long to
drain and then stops regardless. On a healthy run the pipes close in milliseconds and this
never expires. `test/e2e.js` deliberately spawns such a grandchild and asserts the run still
returns.
</details>

### Safety

| Key | Default | Notes |
|---|---|---|
| `relay.enabled` | `true` | Disabling it prints a warning naming what becomes unsupervised. |
| `relay.timeoutMs` | `300000` | No answer inside this window is a **deny**. |
| `relay.rules` | all three | `git`, `destructive-fs`, `network-egress`. Trim if a category is pure noise for you. An **empty or unset** list means all of them, never none. |

### Delivery

| Key | Default | Notes |
|---|---|---|
| `push.enabled` | `true` | Web Push, encrypted end to end. Needs HTTPS or localhost. |
| `push.subject` | example address | A real `mailto:` or `https:` contact. Push services want one. |
| `ntfy.enabled` | `false` | **Posts reply text in plaintext to a public server.** Off for a reason. |
| `ntfy.topic` | `""` | |

### Limits

| Key | Default | Notes |
|---|---|---|
| `maxUploadBytes` | 25 MB | Over the limit is a 413, never a silent truncation. |
| `notificationRing` | `30` | Replies kept in memory. The archive keeps everything. |
| `transcriptRing` | `200` | Live step lines kept per engine. |
| `archiveMaxBytes` | 4 MB | `replies.jsonl` and `runs.jsonl` compact to their newer half past this. |
| `watchIntervalMs` | `60000` | The safety net. The server nudges the watcher the instant a message is queued, so this only catches what a nudge missed. |
| `logLevel` | `info` | `debug` `info` `warn` `error`. |

## Environment variables

An explicit table, not a generic `HALYARD_FOO_BAR → foo.bar` transform — a typo in a generic
scheme is silently ignored, and a typo here shows up in `halyard doctor`.

```
HALYARD_DATA_DIR        HALYARD_HOST            HALYARD_PORT
HALYARD_PUBLIC_URL      HALYARD_ENGINE          HALYARD_WORKSPACE
HALYARD_PERMISSION_MODE HALYARD_RELAY           HALYARD_NTFY_TOPIC
HALYARD_LOG_LEVEL       HALYARD_RELAY_RULES     HALYARD_RELAY_TIMEOUT_MS
```

## CLI flags

Only the settings you actually change per-invocation get a flag. A flag for every key is a
CLI nobody can read.

```
--data-dir  --port  --host  --workspace  --engine  --permission-mode
--public-url  --no-relay
```

## Two full examples

<details open>
<summary><b>Careful: one project, supervised</b></summary>

```json
{
  "host": "127.0.0.1",
  "port": 4545,
  "publicUrl": "https://desk.tail1234.ts.net",
  "workspace": "/home/you/code/api",
  "defaultEngine": "claude",
  "permissionMode": "default",
  "relay": { "enabled": true, "rules": ["git", "destructive-fs", "network-egress"] },
  "push": { "enabled": true, "subject": "mailto:you@example.com" }
}
```
The agent prompts locally for anything it normally would, and the three dangerous families
additionally stop and ask your phone.
</details>

<details>
<summary><b>Unattended: it gets on with it, you keep the veto</b></summary>

```json
{
  "workspace": "/home/you/code",
  "permissionMode": "bypassPermissions",
  "runTimeoutMs": 3600000,
  "relay": { "enabled": true, "rules": ["git", "destructive-fs", "network-egress"] },
  "push": { "enabled": true, "subject": "mailto:you@example.com" }
}
```
No local prompts at all — so the relay is now the **only** thing standing between an
unattended run and a force push. Do not pair a bypass mode with `relay.enabled: false`
unless you have read [SECURITY.md](../SECURITY.md) and mean it.
</details>

## Runtime files

| File | What it is |
|---|---|
| `halyard.config.json` | this file |
| `token.txt` | the bearer token (`0600`) |
| `push-keys.json` | VAPID keypair (`0600`) |
| `push-subs.json` | subscribed browsers |
| `state.json` | the queue and the reply ring — restored at startup |
| `replies.jsonl` | **every reply, permanently.** The only durable copy. |
| `runs.jsonl` | the cost ledger |
| `messages.log` | last 20 turns, human-readable |
| `threads/<name>.md` | that thread's carried summary |
| `threads/<name>.session` | that thread's agent session id |
| `artifacts/` | files the agent writes for you |
| `uploads/` | files you send from the phone |
| `locks/` | run locks, holding a pid |

A thread's existence **is** its `.md` file — the picker lists the directory. A "no context"
turn truncates that file to empty rather than deleting it; delete it and the thread
disappears from your phone mid-use.
