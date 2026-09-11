/**
 * The capture kinds an ATTACHED machine forwards to its deployment — the
 * "sync lane".
 *
 * `code_change` IS A CAPTURE KIND AND IS DELIBERATELY ABSENT. It is excluded
 * from the backlog drain, so no sync state ever makes one of those bodies owed.
 * Adding it here is one word, and it is a product decision that owes its own
 * disclosure rather than a completeness fix.
 *
 * INTERNAL, not exported from the package index, and that is the same property
 * the module-private constant it replaces had. `@akasecurity/schema` already
 * exports `CAPTURE_EVENT_TYPES_SQL` derived from `EventKind` — FOUR kinds,
 * `code_change` included, with the opposite drift policy — and several reads in
 * this package interpolate it. A three-kind constant on the package's public
 * surface under a neighbouring name is how a later findings read reaches for the
 * wrong one, silently loses `code_change`, and under-reports with nothing
 * failing. An `internal/` module is not that surface.
 *
 * IT LIVES HERE RATHER THAN IN ONE OF ITS TWO READERS because the two now decide
 * opposite things from the same list, and the one-word edit above has to move
 * BOTH of them in the same commit:
 *
 *   - `history-sync.ts` uses it to decide what to SEND.
 *   - `body-retention.ts` uses it to decide what may not be EXPIRED until sent.
 *
 * Written out twice, adding `code_change` to the drain starts owing those bodies
 * while the expiry gate keeps clearing them — bodies owed to a deployment,
 * deleted permanently, with no error anywhere. That is the exact failure the
 * gate exists to prevent, reached through the one edit this comment predicts.
 */
export const OUTBOX_CAPTURE_EVENT_TYPES = ['prompt', 'response', 'tool_use'] as const;

/** The same list as a ready-to-interpolate SQL value list. */
export const OUTBOX_CAPTURE_TYPE_LIST = OUTBOX_CAPTURE_EVENT_TYPES.map((t) => `'${t}'`).join(', ');
