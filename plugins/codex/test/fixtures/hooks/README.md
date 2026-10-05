# Codex hook payloads — recorded shapes

Each file here is the JSON one hook received on stdin from **codex-cli 0.160.0**
(`codex --version`, 2026-10-04), in one `codex exec` session run under an
isolated `$CODEX_HOME` whose only hooks were a PreToolUse and a PostToolUse
entry with matcher `.*` that copied stdin to a file. The session was one turn:
create a one-line text file with the `apply_patch` tool. Codex ran that call
inside a code-mode `exec` (the `exec-` prefix on `tool_use_id`), and the hooks
still fired with `tool_name: "apply_patch"`.

- `apply_patch.pre-tool-use.json`: the patch text arrives under
  `tool_input.command`, the same key `Bash` uses. There is no `input` key.
- `apply_patch.post-tool-use.json`: the same `tool_input`, plus a plain-string
  `tool_response` reporting the exit code and the changed paths.

`test/hooks/recorded-payloads.test.ts` checks the hook field mappings against
these files, and the e2e suite builds its `apply_patch` payload from the
PreToolUse one. If a Codex release moves the patch text to another key, those
tests fail here instead of the hook going quiet in a user's session.

## What was rewritten before commit

- **Paths**: the isolated `$CODEX_HOME` became `/Users/dev/.codex` and the
  working directory became `/Users/dev/project`, in every field that carried
  them (`cwd`, `transcript_path`, the patch's file path and the result text).
- **`model`**: replaced with `<model>`. The hook does not read it.
- **Nothing else was changed.** The ids, the `permission_mode` (the session ran
  with approvals off) and the patch and result text are as received.
