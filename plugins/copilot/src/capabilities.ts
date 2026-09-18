/**
 * What this adapter can actually do, per surface and per event — as data, not
 * as prose.
 *
 * It exists because this plugin covers **three** surfaces whose contracts
 * genuinely differ, and only one of them has ever been observed. A sentence in
 * a SKILL.md saying "prompts cannot be blocked on VS Code" is unfalsifiable
 * once it has been written; a row here is checked against the code that
 * implements it and rendered into that SKILL.md by a test that fails when the
 * two disagree (`test/capability-matrix.test.ts`).
 *
 * Two columns carry the weight:
 *
 *  - **`channel`** is what the adapter DOES on that surface today, not what the
 *    host offers. A host capability this package has not wired reads as `none`,
 *    because that is what a user gets.
 *  - **`verified`** is whether a live recording backs it. Every VS Code row is
 *    `false` and stays `false` until a fixture under
 *    `test/fixtures/vscode-provisional/` is replaced by a recording. The value
 *    of that column is that it decays honestly: shipping code has a way of
 *    reading as observed simply because it is shipping.
 */

/** The three surfaces this one package covers. */
export const SURFACES = ['cli', 'vscode', 'cloud'] as const;
export type Surface = (typeof SURFACES)[number];

/**
 * What the adapter can do about a finding on a given surface and event.
 *
 * `none` is a real answer and the most common one here — it says the event is
 * not wired, or the host offers no channel for it — and it is deliberately not
 * spelled as an absent row: an omitted row reads as an oversight, a `none` row
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
  // ── Copilot CLI — the one surface with recordings ────────────────────────
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
    note: 'Model-authored prose that rides along with the call, rewritten in place through modifiedArgs.',
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
    event: 'userPromptSubmitted',
    subject: 'prompt',
    channel: 'none',
    verified: false,
    note: 'Not wired. The host documents modifiedPrompt, but whether a command hook can use it is contradicted between vendor pages and was not probed.',
  },
  {
    surface: 'cli',
    event: 'postToolUse',
    subject: 'toolResult',
    channel: 'none',
    verified: false,
    note: 'Not wired. modifiedResult is documented and was not observed replacing what the model sees.',
  },
  {
    surface: 'cli',
    event: 'permissionRequest',
    subject: 'toolInput',
    channel: 'none',
    verified: true,
    note: 'Deliberately not a scan point: it fires for the same call as preToolUse and carries a strict subset of its arguments, so scanning here would double-count and still miss description.',
  },

  // ── VS Code agent mode — doc-derived, every row ──────────────────────────
  {
    surface: 'vscode',
    event: 'PreToolUse',
    subject: 'run_in_terminal.command',
    channel: 'block',
    verified: false,
    note: 'Built to the published hookSpecificOutput contract; confirmed against no live install.',
  },
  {
    surface: 'vscode',
    event: 'PreToolUse',
    subject: 'file-write content',
    channel: 'rewrite',
    verified: false,
    note: 'updatedInput is validated against the tool input schema and LAST HOOK WINS, so a user or repo hook returning one discards this.',
  },
  {
    surface: 'vscode',
    event: 'UserPromptSubmit',
    subject: 'prompt',
    channel: 'none',
    verified: false,
    note: 'Not wired, and no block or rewrite channel has been observed on this event.',
  },
  {
    surface: 'vscode',
    event: 'PostToolUse',
    subject: 'tool_response',
    channel: 'none',
    verified: false,
    note: 'Not wired. This host has no output-rewrite field at all — block or warn are the only channels it would ever offer.',
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
