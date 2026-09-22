---
name: halyard-setup
description: Set up Halyard on a new machine, or repair an existing install - data dir, config, workspace and permission mode, the approve/deny relay hooks, push contact, autostart and remote access. Use when installing Halyard somewhere new, when moving it between machines, when the headless agent connects but "requires approval" or does nothing, when "spawn ENOENT" appears on start, or when halyard doctor reports something you need explained.
---

# Setting Halyard up on a machine

Halyard is a server plus a watcher plus a page. Getting it running is easy;
getting it *useful* is a small number of decisions that are easy to get wrong
in ways that look like bugs later. Work through this in order and take the
decisions deliberately rather than accepting defaults.

The CLI already does the mechanical parts. Do not reimplement them - call
`node bin/halyard.js <cmd>` (or `halyard <cmd>` if installed globally) and
spend the effort on the decisions and the verification.

## Before you touch anything

Establish these three facts first; two of the four common failures are
already decided here.

1. **Node version.** `node --version` must be >= 18.17 (`engines` in
   package.json). Below that, fail fast and say so.

2. **An agent CLI is actually installed and runnable.** Halyard spawns it.
   `claude --version` is the usual one.

   The trap: on Windows the thing on PATH is often a `.cmd`/`.bat` shim, or
   a package installed with `--ignore-scripts` whose real binary never got
   linked. Both look fine to `where claude` and then fail at spawn time with
   `spawn claude ENOENT`. Halyard resolves the real executable itself
   (`src/which.js`) and `halyard doctor` prints what will actually be
   spawned, so **trust doctor's engine line over PATH**. If it says
   "postinstall did not run", the repair is a reinstall *without*
   `--ignore-scripts`:

       npm install -g @anthropic-ai/claude-code

3. **Where state will live.** It is deliberately NOT in the repo - a
   `git clean -xdf` must not destroy the install. Resolution order, first
   hit wins: `--data-dir`, `HALYARD_DATA_DIR`, `$XDG_STATE_HOME/halyard`,
   then the platform default:

       Windows   %LOCALAPPDATA%\halyard
       macOS     ~/Library/Application Support/halyard
       Linux     ~/.local/state/halyard

   A relative `--data-dir .` gives fully portable behaviour (USB stick,
   container volume) if that is what is wanted.

## 1. Run setup

    node bin/halyard.js setup

This creates the data dir, mints the bearer token, generates the push
keypair, and writes `halyard.config.json` seeded with the *resolved* values
for this machine rather than nulls. It is safe to re-run: it will not
overwrite an existing config.

It prints the data dir, config path, workspace, engine and the tokened URL.

## 2. Decide the workspace

`workspace` is the directory the agent may touch. It is handed to the agent
twice - as the process cwd, and as `--add-dir` in the engine args - so it is
the real boundary, not a hint.

Defaults to the cwd at first run, which is usually the Halyard checkout.
Ask what it should be, because the blast radius is the whole point:

- **A single repo** - smallest blast radius. Correct default answer.
- **A parent directory of several repos** - convenient, and means an
  unattended run can reach every repo under it. Only with a permission
  mode you have thought about.

Set it with `--workspace`, the `workspace` config key, or
`HALYARD_WORKSPACE`. Note the workspace must contain anything you expect the
agent to edit - including the Halyard checkout itself if you want Halyard to
be able to change its own source.

## 3. Decide the permission mode - the one that matters

**This is the setting that makes people think Halyard is broken.** Get it
explicitly right and say out loud which was chosen.

`permissionMode` defaults to `"default"`, under which the agent applies its
normal prompting rules. Headless there is nobody to prompt, so anything
needing permission is simply **refused**. The symptom is a bridge that works
perfectly, replies that arrive on time, and an agent that says every action
"requires approval" and changes nothing. That is not a misconfiguration and
not a bug - it is the conservative default doing exactly what it says.

The three profiles:

    default             Agent prompts, nobody answers, so nothing happens.
                        Fine for read-only questions. Not for real work.

    acceptEdits         File edits pass without a local prompt. Shell
                        commands STILL go through the approve/deny relay to
                        the phone. This is the narrow grant and the right
                        answer for most installs.

    bypassPermissions   No local prompts at all, shell included. The relay
                        becomes the ONLY thing between an unattended run and
                        a force push. Read SECURITY.md before choosing it.

Recommend `acceptEdits` with `relay.enabled: true`. Pair any loosening with
a narrower `workspace` - narrowing costs nothing and bounds the damage.

`halyard doctor` will warn on every run once this is loosened:

    !  permissionMode is "acceptEdits". Tool calls will not prompt locally,
       so the approve/deny relay is your only backstop.

That warning is correct and should not be suppressed.

## 4. Wire the approve/deny relay hooks

    node bin/halyard.js hook-config

This **prints** JSON and deliberately does not write it - it belongs in a
file the agent owns, and silently editing someone's agent settings is not a
surprise this project hands out. Paste it into `.claude/settings.json` in
the **workspace** directory.

Two things to check afterwards, because both fail silently:

- The `matcher` must name every tool that can run a shell
  (`Bash|PowerShell`), not just Bash. A CLI that also ships a PowerShell
  tool walks straight around a Bash-only matcher - and under a loosened
  permission mode, "unrelayed" means "runs, unprompted".
- The matcher and the `RELAYED_TOOLS` set inside
  `hooks/permission-relay.js` must agree. A tool missing from the matcher
  never reaches the hook; a tool missing from `RELAYED_TOOLS` reaches it and
  is waved through.

The hooks are written to no-op without `HALYARD_HEADLESS=1` (the watcher
sets it on every run), so they are safe to leave in a settings.json that
your own interactive sessions in that directory also read. If interactive
sessions ever start hanging on approval, that property has broken - move the
hooks to a settings file only the headless runs use.

Note the steer hook needs an agent CLI that has a pre-tool hook at all;
today that means Claude Code. Other engines are marked un-steerable by
doctor and by the page, which is expected rather than a fault.

## 5. Set the push contact

`push.subject` ships as `mailto:you@example.com`. Push services use it to
reach the operator and delivery is unreliable until it is a real `mailto:`
or `https:` value. Ask for the address rather than inventing one - it is
handed to a third-party service.

Push subscribers are created by opening the page on the phone and allowing
notifications; there will be zero until someone does.

## 6. Verify, in this order

    node bin/halyard.js doctor

Read every line. Specifically confirm: token present, workspace exists,
the engine line shows a real executable (not a problem string), relay `on`,
and the permission mode is the one you chose.

Then start it:

    node bin/halyard.js start

Server and watcher run in one foreground process on 127.0.0.1:4545 by
default, and it dies with the terminal.

Open the tokened URL - `node bin/halyard.js token --url` prints it.

**Do not open `public/index.html` directly.** It takes its token from the
query string and calls root-relative `/api/...` endpoints, so on a `file://`
origin it paints perfectly and connects to nothing. That looks exactly like
a broken build and is not one. The only URLs that work are the tokened ones.

Finish by sending a real message from the page and confirming a reply comes
back. A green doctor with an untested round trip is not a verified install.

## 7. Optional: survive a reboot

    node bin/halyard.js install-service

Writes a scheduled-task script (Windows), launchd plist (macOS) or systemd
unit (Linux) into the data dir and **prints** the command to register it.
It does not register it for you - that is a system-wide, hard-to-reverse
change that needs the operator's own hands.

## 8. Optional: reach it off the machine

Nothing is exposed beyond 127.0.0.1 until you set `publicUrl` and put a
tunnel in front of it. See `docs/REMOTE-ACCESS.md`. Do this last, and only
after the permission mode and relay are settled - the order matters.

## Record what you did, off the repo

Write a short setup record for the machine: paths chosen, workspace,
permission mode and why, what is still open. Keep it **out of the repo**
(the data dir is a good home) because it is machine-specific, and keep
secrets out of it - record the *command that prints* a token, never the
token. `diff/SETUP-NOTES.txt` in this project is an example of the shape.

## When it stops working

Run doctor first; it answers most of it.

| doctor says | means | fix |
| --- | --- | --- |
| engine "is not on PATH" | CLI moved or was uninstalled | reinstall, or set `engines.<name>.command` to an absolute path |
| engine "wrapper, which cannot be run without a shell" | the command is a `.bat`/`.cmd` launching an interpreter | point `engines.<name>.command` at the real executable it wraps |
| engine "postinstall did not run" | installed with `--ignore-scripts` | reinstall without that flag |
| "run lock held by pid N ... (holder is GONE - will be reaped)" | a previous run died badly | nothing - it reaps itself |
| token MISSING | never set up, or data dir changed | `halyard setup`, and check `HALYARD_DATA_DIR` |
| server "not reachable" | not running, or a different data dir/port | start it; confirm doctor and the server agree on the data dir |

Two more that doctor cannot see:

- **Agent replies but does nothing, saying "requires approval".** Permission
  mode, section 3. Nearly always this.
- **Page loads but every panel is empty.** Fetch failures are caught and
  swallowed by design - a phone on a train must not throw dialogs - so an
  expired or wrong token shows as empty panels, not an error. Reopen with a
  fresh tokened URL.

## Changing the page

If the setup involved editing `public/index.html`, run the project's own
gate before declaring it done:

    npm run check    # parses the page's inline script - nothing else catches this
    npm test         # smoke + e2e

The page is served fresh per request and never bundled, so edits apply
instantly and a syntax error in it would otherwise be found by a phone.
