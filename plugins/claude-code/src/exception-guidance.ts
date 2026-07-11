// Copy-paste-complete exception guidance for the enforcement messages. When a
// detection blocks (or redacts), the runtime has already recorded a
// fingerprint-only row in the short-lived blocked-detections ledger and handed
// back a rich reference on `CaptureResult.blockedReferences`; these builders
// turn that into the exact `aka exception approve` command so the user can
// grant an explicit, audited bypass from a terminal. Removal of the flagged
// content stays the first recommendation — the exception is the sanctioned
// escape hatch, offered at the point of failure, never promoted.
//
// The preview and the reference both come from the SAME ledger row
// (BlockedDetectionRef), so the masked value shown can never describe a
// different value than the one `approve <ref>` resolves — and no raw match
// text is handled here at all.
//
// Pure string building (no I/O) so it unit-tests without a hook process. Hook
// entry files run main() on import and must NEVER be imported by tests — that
// is exactly why this lives in its own module instead of inline in the hooks.
import type { BlockedDetectionRef } from '@akasecurity/plugin-sdk';

import { SHADE } from './present.ts';

export interface BlockMessageInput {
  // What was blocked, as it reads mid-sentence: 'prompt' or 'Bash call'.
  subject: string;
  // Comma-joined unique rule ids (uniqueRuleIds output / a joined rule set).
  ruleIds: string;
  // First ledger ref recorded for this capture. Without one the approve
  // command degrades to its bare form, which lists recent blocks to pick from.
  blockedRef?: BlockedDetectionRef | undefined;
  // Extra sentence woven into the first line, between the flag preview and the
  // removal advice — e.g. why a redact policy escalated to a block on
  // executable command text (EXECUTABLE_REDACT_NOTE).
  note?: string | undefined;
}

// The block message (transcript-rendered, so it stays ≤ 5 lines): what was
// flagged (masked preview from the ledger row), removal as the primary fix,
// then the copy-paste-complete exception command with the ledger reference
// baked in, and one help pointer. With a reference the pasted-value form is
// offered as a second, aligned command line — the selector the user already
// has in their clipboard; it only appears when a ledger row is guaranteed,
// because approve-by-value resolves against that same row. Without one the
// command degrades to its bare form, which lists recent blocks to pick from.
export function blockMessage(input: BlockMessageInput): string {
  const preview = input.blockedRef ? ` (${input.blockedRef.maskedValue})` : '';
  const commands = input.blockedRef
    ? [
        `  aka exception approve ${input.blockedRef.reference}       (asks for scope + reason, then resubmit)`,
        '  aka exception approve <value>      (same flow, pasting the blocked value itself)',
      ]
    : ['  aka exception approve       (asks for scope + reason, then resubmit)'];
  const note = input.note ? ` ${input.note}` : '';
  return [
    `AKA blocked this ${input.subject} — flagged ${input.ruleIds}${preview}.${note} Remove the flagged content and resubmit.`,
    'If this is intentional and you accept the risk, grant an exception:',
    ...commands,
    'More: aka exception --help',
  ].join('\n');
}

// One trailing sentence for the redact/warn systemMessage branches: redacted
// values land in the same ledger as blocked ones, so the same approve flow
// applies. Empty when nothing was ledgered — the message is only extended when
// the command would actually find the block.
export function exceptionPointer(references: readonly BlockedDetectionRef[] | undefined): string {
  const ref = references?.[0];
  if (ref === undefined) return '';
  return ` To allow this exact value intentionally, run: aka exception approve ${ref.reference}.`;
}

export interface WithheldBannerInput {
  toolName: string;
  // Most-severe aggregate label for the header line.
  action: 'withheld' | 'redacted';
  // Comma-joined unique rule ids (uniqueRuleIds output), kept per action so a
  // mixed outcome renders as separate `Withheld:` / `Redacted:` lines — one
  // merged list under a single "withheld" label reads as if every rule's
  // surrounding text was removed, when redacted fields WERE delivered with
  // only their spans masked.
  withheldRuleIds?: string | undefined;
  redactedRuleIds?: string | undefined;
  // Warn-action rules flagged in OTHER fields of the same response. Without a
  // line of their own they would vanish: the warn-only systemMessage branch is
  // unreachable once any field was rewritten.
  warnedRuleIds?: string | undefined;
  blockedRef?: BlockedDetectionRef | undefined;
}

// The PostToolUse systemMessage as a shade-glyph banner. A one-line
// "PostToolUse:<tool> says: …" is easy to read past; the full-shade gutter
// makes the intervention unmissable while staying inside the monochrome
// transcript grammar (present.ts: heavier fill = more severe; ANSI is not
// interpreted here, so emphasis is carried by glyph texture only). Same
// 5-line budget as blockMessage in the common single-action case (+1 per
// extra action present).
//
// The masked preview renders on the approve line, not next to the rule list:
// preview and reference come from the same ledger row, and appending one
// preview to a multi-rule list implies the value belongs to the last rule.
export function withheldBanner(input: WithheldBannerInput): string {
  const header = `${SHADE.full}${SHADE.dark}${SHADE.medium}${SHADE.light} AKA ${SHADE.light}${SHADE.medium}${SHADE.dark}${SHADE.full}`;
  const subject = input.action === 'withheld' ? 'The flagged value' : 'Redacted spans';
  const approve = input.blockedRef
    ? `Allow this exact value (${input.blockedRef.maskedValue}) intentionally: aka exception approve ${input.blockedRef.reference}`
    : 'Allow intentionally: aka exception approve';
  return [
    `${header} ${input.toolName} output ${input.action}`,
    ...(input.withheldRuleIds ? [`${SHADE.full} Withheld: ${input.withheldRuleIds}`] : []),
    ...(input.redactedRuleIds ? [`${SHADE.full} Redacted: ${input.redactedRuleIds}`] : []),
    ...(input.warnedRuleIds ? [`${SHADE.full} Also flagged (warn): ${input.warnedRuleIds}`] : []),
    `${SHADE.full} ${subject} never reached the model.`,
    `${SHADE.full} ${approve}`,
    `${SHADE.full} More: aka exception --help`,
  ].join('\n');
}

// The model-visible replacement for a withheld field: states what happened,
// that the content is genuinely absent from context, and that the user should
// be told prominently — the model's own reply is the most visible line in the
// transcript. Deliberately does NOT mention `aka exception approve`: the
// escape hatch is the user's audited decision, not something to nudge an
// agent toward running itself (the user-facing banner carries it instead).
//
// `field` names which part was replaced (e.g. 'stderr', 'file.content') so an
// stderr-only withhold doesn't read as "the whole output was blocked" next to
// perfectly visible stdout.
//
// The placeholder sentence is load-bearing: this text sits where real content
// was, and a read-modify-write flow (Read .env → edit → Write) would otherwise
// persist it back to disk over the user's real file.
//
// The retry sentence is load-bearing too: the no-circumvention directive must
// not read as "never try again". The user can grant an exception out-of-band,
// and the ONLY way it takes effect is the same tool call running again — a
// model that refuses the retry strands the grant unconsumed. Qualified with
// "if it is safe to repeat" so it never instructs re-executing a
// side-effectful command (a deploy, a POST) just to re-fetch its output.
export function withheldToolText(toolName: string, ruleIds: string, field?: string): string {
  const part = field !== undefined && field !== '' ? field : 'output';
  return (
    `[AKA SECURITY] ${toolName} ${part} withheld — flagged ${ruleIds}. ` +
    'The flagged content was not added to your context. ' +
    'This notice is a placeholder, not the real content: the underlying file ' +
    'or command output is unchanged, so never write this notice back to a ' +
    'file or treat it as data. ' +
    'Do not attempt to obtain the withheld content through other channels. ' +
    'Tell the user AKA withheld this output and why. ' +
    'If the user asks again — for example after granting an AKA exception — ' +
    're-run this same tool call if it is safe to repeat: AKA re-evaluates ' +
    'every capture and passes values the user has excepted.'
  );
}
