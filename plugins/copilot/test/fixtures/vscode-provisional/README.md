# VS Code agent-mode hook payloads — PROVISIONAL, not recorded

**No live VS Code session produced any file in this directory.** Every payload
here was written from the published hook documentation and the Copilot Chat
extension's own compatibility note. They sit in a separate directory from
`../cli/` for exactly that reason: those are recordings, these are a
transcription of what a vendor page says, and the distinction stops mattering
to a reader the moment the two live side by side.

A file here is a **statement of what this adapter was built to expect**, not
evidence of what the host sends. Treat every field below as unverified until a
recording replaces it, and move the file into a `vscode/` directory — with a
capture note of its own, in the shape `../cli/README.md` uses — when one does.

## What is unverified, which is everything

There is no useful shorter list, so the fields are grouped by how badly a wrong
guess would hurt rather than by whether anyone is confident in them.

**Would silently scan nothing** (the adapter finds no field table, or finds one
whose keys the payload does not carry, and allows the call having read nothing):

- The tool ids: `run_in_terminal`, `create_file`, `replace_string_in_file`,
  `insert_edit_into_file`, `multi_replace_string_in_file`, `apply_patch`,
  `edit_notebook_file`, `read_file`, `fetch_webpage`, `mcp_*`. The vendor's own
  pages disagree with themselves here — the hook samples use
  `runTerminalCommand`, `editFiles` and `createFile`, while the compatibility
  note uses `run_in_terminal` and `create_file`. This adapter follows the
  compatibility note. If the samples are right, every VS Code enforcement row
  in this package is inert.
- Every key inside `tool_input`. `command`, `explanation`, `content`,
  `newString`, `code`, `input`, `newCode` are each a guess at one tool's
  argument name.
- Whether `tool_input` is camelCase under snake_case tool ids at all. The
  extension source is described as sending camelCase input keys under
  snake_case tool ids, which is an unusual enough pairing to be worth
  re-checking first.

**Would silently mis-route the decision**:

- That `hookSpecificOutput.permissionDecision` is the deny channel and
  `hookSpecificOutput.updatedInput` the rewrite channel, and that `updatedInput`
  is validated against the tool's own input schema (so a partial object is
  rejected and the whole bag must be sent).
- That **last hook wins** on `updatedInput`, so a user's or repo's own
  PreToolUse hook returning one silently discards this adapter's. Nothing here
  detects that, and what the audit row should say when it happens is an open
  question.
- That matchers are parsed and then ignored, so the hook spawns for **every**
  tool call. The adapter's unknown-tool fast path is built for this being true;
  if it is false the fast path is merely unused rather than wrong.

**Would change the failure convention**:

- That exit 2 blocks and everything else fails open. The larger unknown behind
  it is _which harness the 1.135 "Local" session target actually runs_ — the
  extension-host `ChatHookService` (PascalCase, fail-open) or the agent-host
  Copilot-SDK harness (camelCase, `preToolUse` fail-CLOSED). Until that is
  settled, "VS Code fails open" is not one convention but two possibilities.
  This adapter prints an explicit allow on `preToolUse` regardless, which is
  correct either way — that is the point of the wrapper.

**Envelope fields, each optional in a way the CLI's are not**:

- `session_id` is documented as present _only when known_.
- `cwd` is sent _only when the hook entry declares one_; the spawn cwd
  otherwise defaults to the home directory, which is not the workspace.
- `transcript_path` points into
  `workspaceStorage/<hash>/GitHub.copilot-chat/transcripts/<id>.jsonl` and is
  **declared unstable by the vendor**.
- `hook_event_name` is the one field documented as present on every event, which
  is why `../../src/hooks/dialect.ts` tests it first.

## Provenance of the field table, stated plainly

The plan for this work required these fixtures to be written **before**
`VSCODE_SCANNABLE_FIELDS`, so that the table was derived from them rather than
the reverse. That ordering was **not** followed: the table was written first,
from the same vendor pages, and these files were written afterwards.

The consequence is worth being exact about. These fixtures and that table agree,
and their agreement is **not evidence of anything** — they have one source and
one author, and a fixture written to match a table proves only that someone
wrote them to match. What they still buy is a fixed point: a change to either
side now has to move the other, and `../../test/fixture-provenance.test.ts` is what
enforces that. They do not corroborate the table, and nothing here should be
read as though they do.

## Files

Each is one event's stdin payload. `PreToolUse` carries a `run_in_terminal`
call because that is the tool the enforcement path is built around; the others
carry the minimum envelope the documentation describes.
