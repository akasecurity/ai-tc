# VS Code agent mode hook payloads — PROVISIONAL, not recorded

**No live VS Code session produced any file in this directory.** Every one of
them was written from vendor documentation and from the Copilot Chat extension's
published behaviour, and is a statement of what the payload is _believed_ to look
like. That is why this directory sits beside `../cli/` rather than inside it:
those eight files are recordings from a real session on Copilot CLI 1.0.83, and a
doc-derived specimen filed among them would be read as one.

`../../fixture-provenance.test.ts` is what keeps the two apart — a file under
`cli/` with no paragraph in that directory's README describing its capture fails
there.

## What these are for

They are the shape the VS Code half of this adapter is written against: the
dialect sniff (`src/hooks/dialect.ts`) and the VS Code `SCANNABLE_FIELDS` table
(`src/hooks/pre-tool-use-decision.ts`) are both built **from these files**, not
the other way round. Writing the fixtures to match a table already in the tree
would prove nothing at all.

Every capability the adapter claims on this surface is marked `verified: false`
in `src/capabilities.ts` and is stated as unconfirmed in `skills/setup/SKILL.md`.
Replacing a file here with a recording is what earns a `verified: true`.

## Sources

- VS Code's chat-hooks documentation (`code.visualstudio.com`, "Agent mode
  hooks"), which supplies the eight PascalCase event names, the common envelope
  (`hook_event_name`, `timestamp`, `session_id`, `transcript_path`, `cwd`), the
  `hookSpecificOutput.permissionDecision` verdict, `updatedInput`, exit 2 as the
  block channel, and the 30 s timeout with SIGTERM then SIGKILL after 5 s.
- The Copilot Chat extension's own tool ids as they appear in VS Code's
  language-model tool registry: `run_in_terminal`, `create_file`,
  `replace_string_in_file`, `insert_edit_into_file`,
  `multi_replace_string_in_file`, `apply_patch`, `edit_notebook_file`,
  `read_file`, `fetch_webpage`, and the `mcp_*` prefix.

## Every field whose presence, casing or type is unverified

Read this list as the scope of what a live recording would settle. Nothing here
is asserted by the adapter beyond "if it is present and a string, scan it".

- **`session_id`** — documented as sent _only when known_, so its absence is
  expected on some events and is not an error. `detectDialect` places a payload
  without it on `hook_event_name` alone for this reason.
- **`cwd`** — documented as sent _only when the hook entry declares one_. The
  spawn's own working directory defaults to the **home directory**, so the
  adapter deliberately does not fall back to `process.cwd()` on this host.
- **`transcript_path`** — documented as unstable, pointing under
  `workspaceStorage/<hash>/GitHub.copilot-chat/transcripts/<id>.jsonl`. The hash
  and the layout in these files are placeholders.
- **`tool_input` key names, per tool.** The keys in `PreToolUse.json` and
  `PostToolUse.json` (`command`, `explanation`, `isBackground`) are the
  `run_in_terminal` tool's published input schema. Whether the hook receives
  them under exactly those names — and camelCase, which the docs state but no
  recording confirms — is unverified. Whether `updatedInput` is honoured per
  tool, and whether a user's or repo's own hook returning one silently discards
  this adapter's (documented: **last hook wins**), is unverified too.
- **`tool_response`** — documented as a **string**, not an object. The value here
  is the CLI recording's own `textResultForLlm`, reused so the two surfaces'
  fixtures describe the same command; VS Code's real wording is unknown.
- **`source` on `SessionStart`** — the set of values it can take was not observed.
  `startup` here is a placeholder.
- **`SubagentStart` / `SubagentStop` / `PreCompact`** carry nothing beyond the
  common envelope in these files. Whether they carry more is unverified; they are
  present so the event vocabulary has a file per member rather than a gap that
  reads as "this event does not exist".
- **`UserPromptSubmit`'s block and rewrite channels.** Whether `continue: false`,
  a `stopReason`, or an updated-prompt field are honoured here is unknown, so the
  adapter records this event and does not act on it.
- **No `matcher` is honoured.** VS Code parses matchers and ignores them, so the
  hook is spawned for **every** tool call. That is why the unknown-tool exit in
  `src/hooks/pre-tool-use.ts` runs before the config load and before the store
  opens: on this host it is the common path, not the rare one.

## What is NOT a fixture question

The failure convention. VS Code fails **open** — exit 2 blocks, and any other
non-zero exit, invalid JSON or a timeout is a non-blocking warning — while the
Copilot CLI's `preToolUse` denies on a crash. The adapter prints an explicit
allow on `preToolUse` in both dialects anyway, which is correct under either
reading; see `src/hooks/shared.ts`.
