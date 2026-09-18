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

**Only the pre-tool-use event is wired.** Prompts are not captured on any
surface here, tool results are not scanned, and there is no history backfill —
so a secret pasted into a prompt reaches the model, is not recorded by this
plugin, and appears in no finding. `aka scan` and the dashboard cover the
working tree after the fact; nothing covers the conversation.

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
otherwise stays out of the way. A warning it wants to show you goes to stderr,
because the CLI documents no message field on this event.

**A warn may reach only the CLI's log, not your screen.** The hooks reference
describes stderr surfacing for a FAILING hook ("logged as a hook failure"); what
a CLI that exits 0 does with a hook's stderr is not documented and was not
observed here. So under `redactFallback: warn` — the shipped default — the call
goes through and the notice may end up in the debug log rather than in front of
you, which makes a warn hard to tell from `monitor` on this host. Set
`redactFallback` to `block` if a redact on command text has to be visible.

**The cloud coding agent is captured only where the repository asks for it.**
It reads `.github/hooks/*.json` on the **default branch** and nowhere else, and
it has no local store of its own.

### Capability matrix

| Surface | Event               | Subject                 | Channel | Verified | Why                                                                                                                                                                                   |
| ------- | ------------------- | ----------------------- | ------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| cli     | preToolUse          | bash.command            | block   | yes      | A deny on stdout with exit 0 blocks the call; masking command text would change what runs, so a redact policy follows redactFallback instead of rewriting.                            |
| cli     | preToolUse          | bash.description        | rewrite | yes      | Model-authored prose that rides along with the call, rewritten in place through modifiedArgs.                                                                                         |
| cli     | preToolUse          | apply_patch.input       | rewrite | no       | No payload for this tool was recorded, so the argument name is unverified; a wrong name costs a silent skip rather than a wrong answer.                                               |
| cli     | userPromptSubmitted | prompt                  | none    | no       | Not wired. The host documents modifiedPrompt, but whether a command hook can use it is contradicted between vendor pages and was not probed.                                          |
| cli     | postToolUse         | toolResult              | none    | no       | Not wired. modifiedResult is documented and was not observed replacing what the model sees.                                                                                           |
| cli     | permissionRequest   | toolInput               | none    | yes      | Deliberately not a scan point: it fires for the same call as preToolUse and carries a strict subset of its arguments, so scanning here would double-count and still miss description. |
| vscode  | PreToolUse          | run_in_terminal.command | block   | no       | Built to the published hookSpecificOutput contract; confirmed against no live install.                                                                                                |
| vscode  | PreToolUse          | file-write content      | rewrite | no       | updatedInput is validated against the tool input schema and LAST HOOK WINS, so a user or repo hook returning one discards this.                                                       |
| vscode  | UserPromptSubmit    | prompt                  | none    | no       | Not wired, and no block or rewrite channel has been observed on this event.                                                                                                           |
| vscode  | PostToolUse         | tool_response           | none    | no       | Not wired. This host has no output-rewrite field at all — block or warn are the only channels it would ever offer.                                                                    |
| cloud   | preToolUse          | bash.command            | block   | no       | Speaks the CLI protocol, so the adapter behaves identically — but it runs only where the repository commits a hook on its default branch, and ask is coerced to deny there.           |
