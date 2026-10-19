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

**The VS Code half is built to the published contract and confirmed against no
live install.** Every VS Code row below is marked unverified for that reason,
and the fixtures it was written from sit in a separate
`test/fixtures/vscode-provisional/` directory saying so. Treat those rows as
what the vendor documents, not as what was seen to happen.

**Only the pre-tool-use event ENFORCES.** Four events are wired — the session
start, the prompt, the tool call and the tool result — but only the tool call
can be stopped or rewritten. Your prompts and the tool output the model reads
**are** captured, scanned and recorded, so a secret in either shows up as a
finding on the dashboard; **neither can be withheld or masked.** A `block` or
`redact` policy on one of those is recorded as a finding and the text goes to
the model unchanged. AKA says so as a message under VS Code; on the CLI it
writes the notice to stderr. In `-p` mode, the only mode observed, the CLI did
not show a successful hook's stderr: it appeared only in Copilot's debug log,
and only because debug logging was enabled (`--log-level debug`). Whether an
interactive session shows it has not been measured. It never pretends it
enforced.

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

| Surface | Event               | Subject                 | Channel | Verified | Why                                                                                                                                                                                                                                |
| ------- | ------------------- | ----------------------- | ------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| cli     | preToolUse          | bash.command            | block   | yes      | A deny on stdout with exit 0 blocks the call; masking command text would change what runs, so a redact policy follows redactFallback instead of rewriting.                                                                         |
| cli     | preToolUse          | bash.description        | rewrite | yes      | Model-authored prose that rides along with the call, rewritten in place through modifiedArgs.                                                                                                                                      |
| cli     | preToolUse          | apply_patch.input       | rewrite | no       | No payload for this tool was recorded, so the argument name is unverified; a wrong name costs a silent skip rather than a wrong answer.                                                                                            |
| cli     | sessionStart        | session                 | none    | yes      | Opens the session root every later capture hangs off, and records the host, harness and project inventory. It decides nothing and emits nothing — there is no verdict to reach on a session start.                                 |
| cli     | userPromptSubmitted | prompt                  | none    | yes      | Captured and scanned; nothing can be stopped or rewritten. modifiedPrompt is documented and was not observed from a command hook, so a block or redact policy is recorded and the prompt is sent unchanged.                        |
| cli     | postToolUse         | toolResult              | none    | yes      | Captured and scanned; nothing can be withheld. The tool has already run, and modifiedResult is documented but was not observed replacing what the model sees, so a finding is recorded and the output reaches the model unchanged. |
| cli     | permissionRequest   | toolInput               | none    | yes      | Deliberately not a scan point: it fires for the same call as preToolUse and carries a strict subset of its arguments, so scanning here would double-count and still miss description.                                              |
| vscode  | PreToolUse          | run_in_terminal.command | block   | no       | Built to the published hookSpecificOutput contract; confirmed against no live install.                                                                                                                                             |
| vscode  | PreToolUse          | file-write content      | rewrite | no       | updatedInput is validated against the tool input schema and LAST HOOK WINS, so a user or repo hook returning one discards this.                                                                                                    |
| vscode  | SessionStart        | session                 | none    | no       | Opens the session root, as on the CLI. A payload carrying no cwd declines without opening the store, because this host spawns a hook from the home directory unless the entry declared one.                                        |
| vscode  | UserPromptSubmit    | prompt                  | none    | no       | Captured and scanned; nothing can be stopped or rewritten. This host blocks through exit 2, which no path in this adapter takes, so a block or redact policy is recorded and the prompt is sent unchanged.                         |
| vscode  | PostToolUse         | tool_response           | none    | no       | Captured and scanned; nothing can be withheld. This host has no output-rewrite field at all, and its whole-result block has never been driven, so a finding is recorded and the output reaches the model unchanged.                |
| cloud   | preToolUse          | bash.command            | block   | no       | Speaks the CLI protocol, so the adapter behaves identically — but it runs only where the repository commits a hook on its default branch, and ask is coerced to deny there.                                                        |
