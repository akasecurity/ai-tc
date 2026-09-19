---
name: aka-setup
description: Show what AKA Security covers in GitHub Copilot on this machine, and what it cannot.
---

# AKA setup — GitHub Copilot

You are helping someone understand the AKA Security plugin for GitHub Copilot on
this machine. AKA works fully locally with **zero backend and zero Docker**:
detection runs in-process and findings persist to a local SQLite store at
`~/.aka/data/aka.db`. Nothing is sent to a service AKA runs.

**This host does not yet ship the guided calibration flow the Claude Code, Codex
and Antigravity plugins carry.** Those wizards read a user's real transcript
history, rate the findings with the model, and propose a posture from the
numbers. None of that is wired here: this plugin reads no Copilot session
history, so there is nothing for a calibration to read and a wizard that invented
numbers would be worse than none. Say so plainly if you are asked. What is here
is live capture, live enforcement on tool calls, and the shared `aka` CLI.

## What to do

1. Confirm the local store exists and say what is in it:

   ```bash
   aka status
   aka findings
   ```

2. Set enforcement per detection pack. The shipped default is **monitor** —
   everything is recorded and nothing is blocked or redacted until someone
   chooses otherwise:

   ```bash
   aka detections
   ```

3. Open the dashboard for the whole picture:

   ```bash
   aka dashboard
   ```

Never describe AKA as protecting something in the table below that it does not.
If the user asks why something was not caught, answer from that table.

## Known limitations

GitHub Copilot is two hosts wearing one hooks file, and they do not have the same
contract. The **Copilot CLI** (and the cloud coding agent, which speaks the same
wire) is the surface this plugin was recorded against. **VS Code agent mode**
reads the same hooks file and fires differently-named events with
differently-shaped payloads, and **no live VS Code session has produced a payload
in this repository** — every row marked unverified below is built to a published
contract and has never been seen working.

Two limitations apply to both surfaces and are the ones worth stating first.

**Prompts are recorded, never stopped.** Neither host has an observed way for a
hook to stop or rewrite a prompt. So a `block` policy on a prompt flags it,
records it, and the prompt still reaches the model — AKA says so in the message
it prints rather than reporting a block it did not perform.

**File-write content is not scanned, in either direction.** The CLI's patch tool
has never been recorded here, so the field table cannot name its arguments; it
scans nothing rather than scanning the wrong thing and reporting success.

| Surface | Event                 | What is scanned                               | What AKA can do | Verified |
| ------- | --------------------- | --------------------------------------------- | --------------- | -------- |
| cli     | userPromptSubmitted   | the prompt you typed                          | warn            | yes      |
| cli     | userPromptTransformed | the scaffolding the host wraps your prompt in | warn            | yes      |
| cli     | preToolUse            | a shell command                               | block           | yes      |
| cli     | preToolUse            | a tool call's description text                | rewrite         | yes      |
| cli     | preToolUse            | file-write content                            | none            | no       |
| cli     | postToolUse           | what a tool returns to the model              | rewrite         | no       |
| vscode  | UserPromptSubmit      | the prompt you typed                          | warn            | no       |
| vscode  | PreToolUse            | a terminal command or a file edit             | block           | no       |
| vscode  | PostToolUse           | what a tool returns to the model              | block           | no       |

That table is generated from `src/capabilities.ts`, and
`test/capability-matrix.test.ts` fails when the two disagree in either
direction. Edit the matrix, not the table.

### Row by row

- **cli / userPromptSubmitted — the prompt you typed.** Prompts are recorded and
  flagged, never stopped: no prompt-stop or prompt-rewrite channel has been
  observed on this host, so a block policy reports the finding and the prompt
  still reaches the model.
- **cli / userPromptTransformed — the scaffolding the host wraps your prompt
  in.** The host rewraps your prompt with its own context before the model sees
  it; that form is scanned too, and recorded only when it carries something your
  own text did not.
- **cli / preToolUse — a shell command.** A shell command carrying a flagged
  value is denied outright. It cannot be masked in place, because rewriting a
  command changes what runs — so a redact policy follows this workspace's redact
  fallback instead.
- **cli / preToolUse — a tool call's description text.** Model-authored text
  riding alongside a command does not execute, so a flagged value there is masked
  in place and the call proceeds.
- **cli / preToolUse — file-write content.** File writes are not scanned in
  either direction: the CLI's patch tool has never been recorded here, so the
  field table cannot name its arguments and scans nothing rather than scanning
  the wrong thing.
- **cli / postToolUse — what a tool returns to the model.** A flagged tool result
  is replaced before the model reads it — masked for a redact policy, withheld
  for a block. The replacement channel is documented by the vendor and has not
  been seen working here.
- **vscode / UserPromptSubmit — the prompt you typed.** As on the CLI, prompts
  are recorded and flagged but never stopped. Nothing in this repository has
  driven a VS Code session at all.
- **vscode / PreToolUse — a terminal command or a file edit.** Built to the
  published VS Code agent-mode hook contract and not confirmed against a live
  install. The tool ids and their input field names come from a vendor page that
  contradicts another vendor page.
- **vscode / PostToolUse — what a tool returns to the model.** VS Code has no
  field for replacing a tool result, so a redact policy escalates to withholding
  the whole result rather than masking part of it.

### Two more things this host does not do

**A redaction on the CLI is silent to you.** The CLI's rewrite channel is a
single-key output with nowhere to carry a note, so when AKA masks a value in a
tool call or a tool result, the model is told and you are not. The finding is in
`aka findings` and on the dashboard either way.

**The cloud coding agent is not covered.** It speaks the same wire as the CLI,
but nothing installs this plugin on a runner and nothing here has been driven
against it. It is absent from the table above rather than listed as unverified,
because the difference is not confidence — it is that no hook runs there at all.
