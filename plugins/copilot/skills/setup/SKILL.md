---
name: aka-setup
description: Set up AKA Security for GitHub Copilot — what this host can enforce, and what it cannot.
---

# AKA setup — GitHub Copilot

AKA works fully locally with **zero backend and zero Docker**: detection runs
in-process and findings persist to a local SQLite store at `~/.aka/data/aka.db`.

**The calibration wizard is not wired on this host yet.** The Claude Code, Codex
and Antigravity plugins each run a full calibration → triage → remediation flow
from this skill; this adapter ships the live enforcement half only. Until the
wizard lands, use the `aka` CLI directly (`aka init`, `aka detections`,
`aka scan`) and read the dashboard with `aka dashboard`. Do not describe a
calibration step to the user as though it exists here.

## Install — Copilot CLI

The plugin is installed from an unpacked copy of its npm package. There is no
marketplace entry for it yet. Run these from a folder of their own, and keep
that folder: updates are taken from it. The first line is safe to run again: it
reuses an existing `aka-copilot` folder rather than failing.

```sh
mkdir -p aka-copilot && cd aka-copilot
tar -xzf "$(npm pack @akasecurity/ai-tc-copilot --silent)"
copilot plugin install ./package
copilot plugin list
aka init
```

To update, from inside that same `aka-copilot` folder:

```sh
rm -rf package
tar -xzf "$(npm pack @akasecurity/ai-tc-copilot --silent)"
copilot plugin update aka-copilot
```

`copilot plugin update` re-copies the `package` folder into the installed
plugin. It does not fetch a newer version itself: the newer version is whatever
`npm pack` just unpacked there. Removing the old `package` folder first matters,
because unpacking over it would keep files the newer version deleted, and the
update would copy those too.

What Copilot CLI 1.0.98 was recorded doing with these commands:

- `copilot plugin list` shows `aka-copilot` once the install has landed.
- The installed copy is placed under `$COPILOT_HOME/installed-plugins/_direct/`.
  `COPILOT_HOME` defaults to `~/.copilot`, per `copilot help environment`.
- `copilot plugin uninstall aka-copilot` removes it: `copilot plugin list` no
  longer shows it, the `_direct` folder is gone, and installing again with
  `copilot plugin install ./package` works.

Limits of this install:

- **The CLI warns that this install route is deprecated.** It says direct
  installs from a path are being replaced by `plugin@marketplace` installs.
  A marketplace install of this plugin has not been measured.
- **Hook notices were not seen on the screen.** In `-p` mode, the only mode
  observed, AKA's messages appeared only in the CLI's debug log, with debug
  logging enabled (`--log-level debug --log-dir <dir>`). An interactive
  session has not been measured.
- **Windows is unconfirmed.** The plugin has not been installed and run against
  a real Copilot CLI on Windows, so whether its hook commands survive that
  platform's shell is untested.
- **Updating re-copies the folder the plugin was installed from.** The install
  remembers that folder, and `copilot plugin update aka-copilot` replaces the
  installed copy with whatever the folder holds, an older version included. It
  does not fetch from npm; the update steps above put the newer version in the
  folder first. If that folder has been deleted, update fails and changes
  nothing; AKA keeps running from the installed copy. A `-p` session start was
  observed not to update the plugin; an interactive session has not been
  measured.
- **The cloud coding agent is not covered by this install.** It does not load
  installed plugins; it reads only the repository's `.github/hooks/*.json`.

## Known limitations

This section is the authority on what AKA can actually do on this host. It is
**rendered from `src/capabilities.ts`** and held to it by
`test/capability-matrix.test.ts`, so a row here and the code that implements it
cannot drift apart. Be honest about every one of these if the user asks why
something was not caught — never imply coverage this plugin does not have.

**One package covers three surfaces, and they are not equivalent.** The Copilot
CLI, VS Code agent mode and the cloud coding agent each have their own event
names, payload spelling and failure convention. Which one a session is on
decides what AKA can do in it.

**The VS Code half is built to the published contract and partly confirmed
against a live install.** One agent-mode session on VS Code 1.141.0 with Copilot
Chat 0.69.0 loaded this plugin and ran all four of its hooks; the payloads are in
`test/fixtures/vscode/plugin-load-1.141/`. That session confirmed the session
start, the prompt capture and the tool-result capture, and those three rows
below are marked verified. It also recorded a tool-call capture with a warn
finding and a file-write capture. A deny, an input rewrite, a large-input
refusal and a flagged tool result were never driven, so the block and rewrite
rows stay unverified. Treat an unverified row as what the vendor documents, not
as what was seen to happen.
The doc-derived fixtures the half was first written from still sit in
`test/fixtures/vscode-provisional/`.

**Only the pre-tool-use event ENFORCES.** Four events are wired — the session
start, the prompt, the tool call and the tool result — but only the tool call
can be stopped or rewritten. Your prompts and the tool output the model reads
**are** captured, scanned and recorded, so a secret in either shows up as a
finding on the dashboard; **neither can be withheld or masked.** A `block` or
`redact` policy on one of those is recorded as a finding and the text goes to
the model unchanged. Under VS Code AKA returns the notice as a hook message,
and it appears only in VS Code's "GitHub Copilot Chat Hooks" output channel: in
the recorded session the chat showed nothing from AKA. On the CLI it writes the
notice to stderr. In `-p` mode, the only mode observed, the CLI did not show a
successful hook's stderr: it appeared only in Copilot's debug log, and only
because debug logging was enabled (`--log-level debug`). Whether an interactive
session shows it has not been measured. It never pretends it enforced.

The reason is that neither host has a channel for it that has been seen to
work: the CLI's `modifiedPrompt` and `modifiedResult` are documented and were
never observed, and VS Code blocks through exit 2, which no path in this plugin
takes. A tool result is also too late by construction — the tool has already
run, and what is at stake is only whether its output reaches the model.

**A prompt or tool result too large to scan in time is reported, not
refused.** A field of 32,768 characters or more is scanned in a separate thread
under a deadline. If that scan does not finish, AKA says the text was too large
to scan in time and that it went to the model unchanged. If AKA's scan thread
could not run at all, it says that instead: nothing was checked, the text went
to the model unchanged, and the plugin should be reinstalled if it happens
again — a missing scan thread is an install fault, and every text this large
goes unscanned until it is repaired. Either way it is never treated as clean,
and never stopped: neither event has a channel to stop it with. A structured tool result is read only to a fixed
depth, number of text values and total size; anything past those limits is
reported as unscanned in the same way.

**There is still no history backfill.** Nothing reads the sessions that
happened before AKA was installed, or any session's own transcript on disk.
`aka scan` and the dashboard cover the working tree after the fact.

**Command text is never masked in place.** Rewriting a shell command changes
what runs, so a `redact` policy on command text follows this workspace's
`redactFallback` instead. It ships as `warn`, which means the command runs and
the only trace is a message.

**Under VS Code, a warn is not shown in the chat.** AKA returns a warn, and the
notice that a redact fell back to warn, as a hook message. In the recorded
session VS Code accepted it and showed it only in the "GitHub Copilot Chat
Hooks" output channel, so the user never saw it, and a warn there is hard to
tell from `monitor`. Set `redactFallback` to `block` if a redact on command text
has to be visible; a VS Code deny itself was never driven, so that row stays
unverified.

**Under VS Code, a rewrite can be silently discarded.** That host validates
`updatedInput` against the tool's own input schema and applies **last hook
wins**, so a user's or a repository's own `PreToolUse` hook returning one
replaces AKA's.

**Under VS Code, matchers are ignored.** The hook is spawned for every tool call
the agent makes, including ones AKA has no field table for. Those exit
immediately, write nothing and open no store.

**On the CLI a crashing hook denies the call.** `preToolUse` is the one
fail-closed event there: a hook that exits non-zero other than 2 denies the tool
call, exit 2 denies, and a timed-out one allows. Empty stdout is none of those —
the hooks reference documents it as "default behavior", meaning the call goes to
your own permission flow. So AKA writes **nothing** when it has no verdict, and
what it guarantees is that no path exits non-zero.

**AKA never pre-approves a call on the CLI.** `permissionDecision: "allow"` is a
verdict that the tool executes, so printing one per clean call would suppress
the approval prompts your own Copilot settings would have raised. AKA emits a
verdict only to deny, rewrites arguments only through `modifiedArgs`, and
otherwise stays out of the way. A warning it has is written to stderr, because
the CLI documents no message field on this event.

**In `-p` mode a warn reached only the CLI's debug log, not the screen.** The
hooks reference describes stderr surfacing for a FAILING hook ("logged as a
hook failure") and says nothing about one that exits 0. Observed on Copilot
CLI 1.0.98 in `-p` mode: a successful hook's stderr appears nowhere in the
CLI's own output, and only in the debug log (`--log-level debug --log-dir
<dir>`), as `[rust:hooks] [hook stderr] …` lines. So under `redactFallback:
warn` — the shipped default — the call goes through and the notice is in that
log rather than in front of you, which makes a warn hard to tell from
`monitor` on this host. An interactive session has not been measured. Set
`redactFallback` to `block` if a redact on command text has to be visible.

**The cloud coding agent is captured only where the repository asks for it.**
It reads `.github/hooks/*.json` on the **default branch** and nowhere else, and
it has no local store of its own.

**Where the session's activity goes may not be shown to you.** On a machine
attached to the organization's control plane, the Claude Code and Codex plugins
print one line at session start: forwarding everything, forwarding for the
enrolled repository the session is in, or local-only. This adapter's
session-start hook has no message field on either surface, so it writes that
line to **stderr**, together with its other once-per-session notices: that a
newer AKA binary is on the machine than this plugin, that a warn-era store's
block and redact categories were kept at warn, and that the store path is
redirected. Its stdout stays empty. In `-p` mode the CLI did not show a
successful hook's stderr (see above), so these lines were seen only in the
debug log, with debug logging enabled; an interactive session is unmeasured.
`aka status` shows whether this machine is attached, whether it sends
everything or only enrolled repositories, and which repositories are enrolled.

### Capability matrix

| Surface | Event               | Subject                           | Channel | Verified | Why                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------- | ------------------- | --------------------------------- | ------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| cli     | preToolUse          | bash.command                      | block   | yes      | A deny on stdout with exit 0 blocks the call; masking command text would change what runs, so a redact policy follows redactFallback instead of rewriting.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| cli     | preToolUse          | bash.description                  | rewrite | yes      | Model-authored prose that rides along with the call, rewritten in place through modifiedArgs. Scanned for secrets and PII only: the command-risk rules judge bash.command, never this prose.                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| cli     | preToolUse          | apply_patch.input                 | rewrite | no       | No payload for this tool was recorded, so the argument name is unverified; a wrong name costs a silent skip rather than a wrong answer.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| cli     | sessionStart        | session                           | none    | yes      | Opens the session root every later capture hangs off, and records the host, harness and project inventory. It decides nothing and emits nothing — there is no verdict to reach on a session start.                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| cli     | userPromptSubmitted | prompt                            | none    | yes      | Captured and scanned; nothing can be stopped or rewritten. modifiedPrompt is documented and was not observed from a command hook, so a block or redact policy is recorded and the prompt is sent unchanged.                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| cli     | postToolUse         | toolResult                        | none    | yes      | Captured and scanned; nothing can be withheld. The tool has already run, and modifiedResult is documented but was not observed replacing what the model sees, so a finding is recorded and the output reaches the model unchanged.                                                                                                                                                                                                                                                                                                                                                                                                                          |
| cli     | permissionRequest   | toolInput                         | none    | yes      | Deliberately not a scan point: it fires for the same call as preToolUse and carries a strict subset of its arguments, so scanning here would double-count and still miss description.                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| vscode  | PreToolUse          | run_in_terminal.command           | block   | no       | The capture and the warn were recorded in test/fixtures/vscode/plugin-load-1.141/: the call was stored with its finding, and the warn systemMessage reached only the hooks output channel, never the chat. A deny through hookSpecificOutput was never driven, so the block itself is unverified.                                                                                                                                                                                                                                                                                                                                                           |
| vscode  | PreToolUse          | run_in_terminal.explanation, goal | rewrite | no       | Model-authored prose that rides along with the call; both fields were recorded in test/fixtures/vscode/plugin-load-1.141/. They do not execute, so a redact rewrites them in place through updatedInput, which was never driven. This host takes updatedInput only alongside permissionDecision allow, so a redact here also APPROVES the call, suppressing any prompt the user's own settings would have raised. updatedInput is validated against the tool input schema and LAST HOOK WINS, so a user or repo hook returning one discards this. Scanned for secrets and PII only: the command-risk rules judge run_in_terminal.command, never this prose. |
| vscode  | PreToolUse          | file-write content                | rewrite | no       | create_file content was recorded as captured, in test/fixtures/vscode/plugin-load-1.141/. No updatedInput was ever driven; it is validated against the tool input schema and LAST HOOK WINS, so a user or repo hook returning one discards this.                                                                                                                                                                                                                                                                                                                                                                                                            |
| vscode  | SessionStart        | session                           | none    | yes      | Opens the session root as the vscode interface, recorded in test/fixtures/vscode/plugin-load-1.141/. A payload carrying no cwd declines without opening the store; the recorded host sent cwd on every event.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| vscode  | UserPromptSubmit    | prompt                            | none    | yes      | Captured and scanned, recorded in test/fixtures/vscode/plugin-load-1.141/; nothing can be stopped or rewritten. This host blocks through exit 2, which no path in this adapter takes, so a block or redact policy is recorded and the prompt is sent unchanged.                                                                                                                                                                                                                                                                                                                                                                                             |
| vscode  | PostToolUse         | tool_response                     | none    | yes      | Captured and scanned, recorded in test/fixtures/vscode/plugin-load-1.141/ as a string response; nothing can be withheld. This host has no output-rewrite field at all, and its whole-result block has never been driven, so a finding is recorded and the output reaches the model unchanged.                                                                                                                                                                                                                                                                                                                                                               |
| cloud   | preToolUse          | bash.command                      | block   | no       | Speaks the CLI protocol, so the adapter behaves identically — but it runs only where the repository commits a hook on its default branch, and ask is coerced to deny there.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

## Install — VS Code agent mode (beta)

**VS Code agent mode support is beta.** Capture was observed in one agent-mode
session on VS Code 1.141.0 with the built-in GitHub Copilot Chat 0.69.0. That is
the only version it has been seen on. Enforcement is unverified. The capability
matrix above is the authority on which VS Code rows are verified: rely only on a
row marked `yes` as working, and describe every row marked `no` as what the
vendor documents, not as what was seen to happen.

**Load the package from a local directory.** There is no marketplace install for
VS Code. If the Copilot CLI install above has already been done, reuse its
`aka-copilot` folder and skip these two lines, so VS Code loads the same folder
the update steps refresh. Otherwise pack and unpack the npm package, then point
VS Code at the unpacked folder in your user settings:

```sh
mkdir -p aka-copilot && cd aka-copilot
tar -xzf "$(npm pack @akasecurity/ai-tc-copilot --silent)"
```

```json
{
  "chat.plugins.enabled": true,
  "chat.useHooks": true,
  "chat.pluginLocations": { "<absolute path to the unpacked package folder>": true }
}
```

`npm pack` unpacks into a folder named `package`; use its absolute path. VS Code
reads the plugin's own `hooks.json` — no VS Code-specific hooks file is needed —
runs its four hooks and expands `${PLUGIN_ROOT}` in their commands.

**What was observed working: capture only.** In that session AKA recorded the
session start, the prompt, a `run_in_terminal` command, a `create_file` write
and the tool result. A secret-bearing command raised a finding on the dashboard.
Nothing else in the session was driven.

**Not verified.** None of these has been seen to work on VS Code, so do not
promise them:

- blocking a tool call (a deny);
- rewriting a file write (`updatedInput`);
- the large-input refusal;
- scanning an object-shaped tool result.

**AKA's notices are not shown in the chat.** A hook's `systemMessage`, such as a
warn or the first-run notice, appeared only in VS Code's "GitHub Copilot Chat
Hooks" output channel, and the chat showed nothing from AKA. To read them, open
the Output panel and choose the "GitHub Copilot Chat Hooks" channel. Do not tell
a user a warning will appear in the chat.

**Caveats that apply here.** Matchers are ignored, so the hook runs for every
tool call, and a rewrite is last-hook-wins, so another hook's `updatedInput` can
discard AKA's. Both are described under Known limitations above.

**The cloud coding agent is not covered by this install.** It reads hooks from
`.github/hooks/*.json` on a repository's default branch and is a separate
surface; see Known limitations.
