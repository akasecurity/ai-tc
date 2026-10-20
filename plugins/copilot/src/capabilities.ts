/**
 * What this adapter can actually do, per surface and per event — as data, not
 * as prose.
 *
 * It exists because this plugin covers **three** surfaces whose contracts
 * genuinely differ, and none of them has been observed in full. A sentence in
 * a SKILL.md saying "prompts cannot be blocked on VS Code" is unfalsifiable
 * once it has been written; a row here is checked against the code that
 * implements it and rendered into that SKILL.md by a test that fails when the
 * two disagree (`test/capability-matrix.test.ts`).
 *
 * Two columns carry the weight:
 *
 *  - **`channel`** is what the adapter can DO ABOUT A FINDING on that surface
 *    today, not what the host offers and not whether the event is wired at all.
 *    A host capability this package has not wired reads as `none`, because that
 *    is what a user gets — and so does a wired event with nothing to enforce
 *    with. Three of the four registered events are `none` for the second
 *    reason: they capture, scan and record, and no host channel this repository
 *    has confirmed lets them stop or rewrite anything. The `note` is what
 *    separates the two cases, and it has to.
 *  - **`verified`** is whether a live recording backs it. A VS Code row is
 *    `true` only where a recording under `test/fixtures/vscode/` shows the
 *    row's claim, and a row whose channel was never driven stays `false` even
 *    where its capture was recorded. The value of that column is that it
 *    decays honestly: shipping code has a way of reading as observed simply
 *    because it is shipping.
 */

/** The three surfaces this one package covers. */
export const SURFACES = ['cli', 'vscode', 'cloud'] as const;
export type Surface = (typeof SURFACES)[number];

/**
 * What the adapter can do about a finding on a given surface and event.
 *
 * `none` is a real answer and the most common one here. It says one of three
 * things, and the `note` is what tells them apart: the event is not wired; the
 * host offers no channel for it; or the event IS wired and captures and scans,
 * and there is simply nothing it can enforce with. It is deliberately not
 * spelled as an absent row — an omitted row reads as an oversight, a `none` row
 * reads as a decision.
 */
export type Channel = 'block' | 'rewrite' | 'warn' | 'none';

export interface Capability {
  surface: Surface;
  /** The event name in that surface's own vocabulary. */
  event: string;
  /** What is being decided about — a field, or the whole call. */
  subject: string;
  channel: Channel;
  /** Whether a live recording of this surface backs the row. */
  verified: boolean;
  /** Why, in one clause a SKILL.md line can be built from. */
  note: string;
}

export const CAPABILITY_MATRIX: readonly Capability[] = [
  // ── Copilot CLI — recorded ───────────────────────────────────────────────
  {
    surface: 'cli',
    event: 'preToolUse',
    subject: 'bash.command',
    channel: 'block',
    verified: true,
    note: 'A deny on stdout with exit 0 blocks the call; masking command text would change what runs, so a redact policy follows redactFallback instead of rewriting.',
  },
  {
    surface: 'cli',
    event: 'preToolUse',
    subject: 'bash.description',
    channel: 'rewrite',
    verified: true,
    note: 'Model-authored prose that rides along with the call, rewritten in place through modifiedArgs. Scanned for secrets and PII only: the command-risk rules judge bash.command, never this prose.',
  },
  {
    surface: 'cli',
    event: 'preToolUse',
    subject: 'apply_patch.input',
    channel: 'rewrite',
    verified: false,
    note: 'No payload for this tool was recorded, so the argument name is unverified; a wrong name costs a silent skip rather than a wrong answer.',
  },
  {
    surface: 'cli',
    event: 'sessionStart',
    subject: 'session',
    channel: 'none',
    verified: true,
    note: 'Opens the session root every later capture hangs off, and records the host, harness and project inventory. It decides nothing and emits nothing — there is no verdict to reach on a session start.',
  },
  {
    surface: 'cli',
    event: 'userPromptSubmitted',
    subject: 'prompt',
    channel: 'none',
    verified: true,
    note: 'Captured and scanned; nothing can be stopped or rewritten. modifiedPrompt is documented and was not observed from a command hook, so a block or redact policy is recorded and the prompt is sent unchanged.',
  },
  {
    surface: 'cli',
    event: 'postToolUse',
    subject: 'toolResult',
    channel: 'none',
    verified: true,
    note: 'Captured and scanned; nothing can be withheld. The tool has already run, and modifiedResult is documented but was not observed replacing what the model sees, so a finding is recorded and the output reaches the model unchanged.',
  },
  {
    surface: 'cli',
    event: 'permissionRequest',
    subject: 'toolInput',
    channel: 'none',
    verified: true,
    note: 'Deliberately not a scan point: it fires for the same call as preToolUse and carries a strict subset of its arguments, so scanning here would double-count and still miss description.',
  },

  // ── VS Code agent mode — recorded where a row says so ───────────────────
  {
    surface: 'vscode',
    event: 'PreToolUse',
    subject: 'run_in_terminal.command',
    channel: 'block',
    verified: false,
    note: 'The capture and the warn were recorded in test/fixtures/vscode/plugin-load-1.141/: the call was stored with its finding, and the warn systemMessage reached only the hooks output channel, never the chat. A deny through hookSpecificOutput was never driven, so the block itself is unverified.',
  },
  {
    surface: 'vscode',
    event: 'PreToolUse',
    subject: 'run_in_terminal.explanation, goal',
    channel: 'rewrite',
    verified: false,
    note: "Model-authored prose that rides along with the call; both fields were recorded in test/fixtures/vscode/plugin-load-1.141/. They do not execute, so a redact rewrites them in place through updatedInput, which was never driven. This host takes updatedInput only alongside permissionDecision allow, so a redact here also APPROVES the call, suppressing any prompt the user's own settings would have raised. updatedInput is validated against the tool input schema and LAST HOOK WINS, so a user or repo hook returning one discards this. Scanned for secrets and PII only: the command-risk rules judge run_in_terminal.command, never this prose.",
  },
  {
    surface: 'vscode',
    event: 'PreToolUse',
    subject: 'file-write content',
    channel: 'rewrite',
    verified: false,
    note: 'create_file content was recorded as captured, in test/fixtures/vscode/plugin-load-1.141/. No updatedInput was ever driven; it is validated against the tool input schema and LAST HOOK WINS, so a user or repo hook returning one discards this.',
  },
  {
    surface: 'vscode',
    event: 'SessionStart',
    subject: 'session',
    channel: 'none',
    verified: true,
    note: 'Opens the session root as the vscode interface, recorded in test/fixtures/vscode/plugin-load-1.141/. A payload carrying no cwd declines without opening the store; the recorded host sent cwd on every event.',
  },
  {
    surface: 'vscode',
    event: 'UserPromptSubmit',
    subject: 'prompt',
    channel: 'none',
    verified: true,
    note: 'Captured and scanned, recorded in test/fixtures/vscode/plugin-load-1.141/; nothing can be stopped or rewritten. This host blocks through exit 2, which no path in this adapter takes, so a block or redact policy is recorded and the prompt is sent unchanged.',
  },
  {
    surface: 'vscode',
    event: 'PostToolUse',
    subject: 'tool_response',
    channel: 'none',
    verified: true,
    note: 'Captured and scanned, recorded in test/fixtures/vscode/plugin-load-1.141/ as a string response; nothing can be withheld. This host has no output-rewrite field at all, and its whole-result block has never been driven, so a finding is recorded and the output reaches the model unchanged.',
  },

  // ── Cloud coding agent — the CLI's protocol, no local store ──────────────
  {
    surface: 'cloud',
    event: 'preToolUse',
    subject: 'bash.command',
    channel: 'block',
    verified: false,
    note: 'Speaks the CLI protocol, so the adapter behaves identically — but it runs only where the repository commits a hook on its default branch, and ask is coerced to deny there.',
  },
] as const;

/** Every row for one surface, in declaration order. */
export function capabilitiesFor(surface: Surface): readonly Capability[] {
  return CAPABILITY_MATRIX.filter((row) => row.surface === surface);
}

/**
 * Whether any row on a surface is backed by a live recording.
 *
 * The question a "Known limitations" section has to answer first, because a
 * surface with no verified row at all is one whose every claim is a reading of
 * a vendor page.
 */
export function surfaceIsVerified(surface: Surface): boolean {
  return capabilitiesFor(surface).some((row) => row.verified);
}
