/**
 * What this adapter can actually DO, per surface and per event — as code.
 *
 * Every other host in this repository has one hook contract, so its limits live
 * in prose in a `SKILL.md` and nowhere else. This package covers TWO hosts whose
 * contracts differ, and one of the two has never been observed at all, so prose
 * alone would decay in the one direction that matters: a limitation stops
 * reading as a limitation once it has been shipping for a while.
 *
 * So the matrix is the artifact and the prose is derived from it.
 * `test/capability-matrix.test.ts` parses `skills/setup/SKILL.md`'s Known
 * limitations table and fails when the two disagree — in both directions, so a
 * row added here without a sentence fails exactly as a sentence outliving its
 * row does.
 *
 * ─── THE `verified` COLUMN IS THE POINT ──────────────────────────────────────
 *
 * `verified: true` means a live session in this repository produced the
 * behaviour, and `test/fixtures/cli/README.md` says which. `verified: false`
 * means the row is built to a published contract and nothing here has seen it
 * work. The risk the column exists against is not that an unverified row is
 * wrong — it is that it stops READING as unverified once it is shipping code.
 * Do not promote a row without a recording.
 */

/** A surface this package's hooks run on. */
export type Surface = 'cli' | 'vscode' | 'cloud';

/**
 * What AKA can do about a finding in one place.
 *
 *  - `block`   — the call, or the whole tool result, is stopped.
 *  - `rewrite` — the value is replaced in place and the call proceeds.
 *  - `warn`    — a note is printed; the content goes out unchanged.
 *  - `none`    — nothing is captured here at all.
 *
 * `warn` is the honest answer for a surface that RECORDS but cannot enforce,
 * and it is deliberately not spelled `block`: a channel the host ignores is
 * worse than no channel, because the user reads an enforcement claim.
 */
export type Channel = 'block' | 'rewrite' | 'warn' | 'none';

export interface Capability {
  surface: Surface;
  /** The host's own event name, in that host's own spelling. */
  event: string;
  /** What is scanned there, in the words a user would recognise. */
  subject: string;
  channel: Channel;
  /** True only when a live session in this repository produced it. */
  verified: boolean;
  /** One sentence, and the text `SKILL.md`'s table must carry verbatim. */
  note: string;
}

/**
 * THE CLOUD SURFACE IS ABSENT FROM THIS TABLE, and that is a claim rather than
 * an omission: no `.github/hooks/aka.json` ships, no runner installs this
 * plugin, and nothing in this package has been driven against the coding agent.
 * A row asserting it speaks the CLI's wire would be true of the host and false
 * of what AKA does there. It joins the table when Phase C does.
 */
export const CAPABILITY_MATRIX: readonly Capability[] = [
  {
    surface: 'cli',
    event: 'userPromptSubmitted',
    subject: 'the prompt you typed',
    channel: 'warn',
    verified: true,
    note: 'Prompts are recorded and flagged, never stopped: no prompt-stop or prompt-rewrite channel has been observed on this host, so a block policy reports the finding and the prompt still reaches the model.',
  },
  {
    surface: 'cli',
    event: 'userPromptTransformed',
    subject: 'the scaffolding the host wraps your prompt in',
    channel: 'warn',
    verified: true,
    note: 'The host rewraps your prompt with its own context before the model sees it; that form is scanned too, and recorded only when it carries something your own text did not.',
  },
  {
    surface: 'cli',
    event: 'preToolUse',
    subject: 'a shell command',
    channel: 'block',
    verified: true,
    note: 'A shell command carrying a flagged value is denied outright. It cannot be masked in place, because rewriting a command changes what runs — so a redact policy follows this workspace’s redact fallback instead.',
  },
  {
    surface: 'cli',
    event: 'preToolUse',
    subject: 'a tool call’s description text',
    channel: 'rewrite',
    verified: true,
    note: 'Model-authored text riding alongside a command does not execute, so a flagged value there is masked in place and the call proceeds.',
  },
  {
    surface: 'cli',
    event: 'preToolUse',
    subject: 'file-write content',
    channel: 'none',
    verified: false,
    note: 'File writes are not scanned in either direction: the CLI’s patch tool has never been recorded here, so the field table cannot name its arguments and scans nothing rather than scanning the wrong thing.',
  },
  {
    surface: 'cli',
    event: 'postToolUse',
    subject: 'what a tool returns to the model',
    channel: 'rewrite',
    verified: false,
    note: 'A flagged tool result is replaced before the model reads it — masked for a redact policy, withheld for a block. The replacement channel is documented by the vendor and has not been seen working here.',
  },
  {
    surface: 'vscode',
    event: 'UserPromptSubmit',
    subject: 'the prompt you typed',
    channel: 'warn',
    verified: false,
    note: 'As on the CLI, prompts are recorded and flagged but never stopped. Nothing in this repository has driven a VS Code session at all.',
  },
  {
    surface: 'vscode',
    event: 'PreToolUse',
    subject: 'a terminal command or a file edit',
    channel: 'block',
    verified: false,
    note: 'Built to the published VS Code agent-mode hook contract and not confirmed against a live install. The tool ids and their input field names come from a vendor page that contradicts another vendor page.',
  },
  {
    surface: 'vscode',
    event: 'PostToolUse',
    subject: 'what a tool returns to the model',
    channel: 'block',
    verified: false,
    note: 'VS Code has no field for replacing a tool result, so a redact policy escalates to withholding the whole result rather than masking part of it.',
  },
];

/** Every surface the matrix describes, in the order it describes them. */
export function surfaces(): Surface[] {
  const seen: Surface[] = [];
  for (const row of CAPABILITY_MATRIX) if (!seen.includes(row.surface)) seen.push(row.surface);
  return seen;
}

/**
 * The rows no live session in this repository has produced.
 *
 * Used by the `SKILL.md` guard to require that the document says so, and worth
 * having as a function rather than a count: a caller that wants to know whether
 * anything is unverified should ask, not remember a number.
 */
export function unverified(): Capability[] {
  return CAPABILITY_MATRIX.filter((row) => !row.verified);
}
