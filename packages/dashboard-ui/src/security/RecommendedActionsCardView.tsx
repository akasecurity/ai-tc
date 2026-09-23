'use client';

import type {
  DismissMethod,
  DismissRecommendation,
  RecommendationSubject,
  RecommendedAction,
  Severity,
} from '@akasecurity/schema';
import { DISMISS_CONFIRMATION } from '@akasecurity/schema';
import {
  Button,
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardHeading,
  CardIcon,
  CardTitle,
  cn,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Skeleton,
  Tag,
  type Tone,
  TONE_SOFT,
} from '@akasecurity/ui-kit';
import { useState } from 'react';

import type { IconComponent } from '../lib/icons.ts';
import { ChoiceGroup } from '../shared/ChoiceGroup.tsx';
import {
  AlertOctagonIcon,
  ExternalShareIcon,
  RedactIcon,
  SlashCircleIcon,
  SparklesIcon,
} from '../shared/icons.tsx';
import { canConfirmDismiss, DISMISS_METHODS, dismissConsequences } from './dismiss-gate.ts';
import { WidgetError } from './widget-shared.tsx';

type RecommendationTone = Extract<Tone, 'critical' | 'primary' | 'teal'>;

// `category` is an extensible string; map the known ones to a tile icon, falling
// back to a generic alert for any new category.
const RECOMMENDATION_ICON: Record<string, IconComponent> = {
  block_credentials: SlashCircleIcon,
  redact_pii: RedactIcon,
  review_external_share: ExternalShareIcon,
};

// Tile color follows the recommendation's severity (a closed enum, robust to new
// categories) and reproduces the original per-category design.
const SEVERITY_TONE: Record<Severity, RecommendationTone> = {
  critical: 'critical',
  high: 'primary',
  medium: 'teal',
  low: 'teal',
};

// Callbacks come from the connected layer (a Server Action in the web-ui
// dashboard), so the view stays data-source-blind.
export interface RecommendedActionsView {
  items: RecommendedAction[];
  isLoading: boolean;
  error: string | null;
  /**
   * Destination for the header's "View all" control. Host-supplied so this package
   * stays router-agnostic. Omitted, the control is not rendered at all — a button
   * that looks live and does nothing reads as a broken feature.
   */
  viewAllHref?: string | undefined;
  applyAction: (id: string) => void;
  /**
   * Close out every open finding of one rule. Resolves `true` when the write
   * landed, which is what closes the dialog — the view cannot read that off
   * `isMutating`, which falls back to false on a refusal exactly as it does on
   * a success, and a dialog that closed either way would report a refused
   * dismissal as a completed one.
   *
   * Keyed by RULE, not by the row's `id`. A row is a category bucket labelled
   * with its most-severe rule and counted on that rule, and it links to that
   * rule's open list — so the set this writes against is the set the label
   * names and the link lands on.
   */
  dismissAction: (request: DismissRecommendation) => Promise<boolean>;
  isMutating: boolean;
  mutationError: string | null;
}

/**
 * The rule a row is counted on, or undefined for a row carrying none.
 *
 * A dismissal needs a rule to write against, so a row without one renders no
 * Dismiss control at all — the same rule the absent `href` follows one branch
 * below, and for the same reason: a button that cannot act must not be drawn as
 * though it can.
 */
function ruleSubject(a: RecommendedAction): RecommendationSubject | undefined {
  return a.subjects.find((s) => s.type === 'rule');
}

export function RecommendedActionsCardView({
  items,
  isLoading,
  error,
  applyAction,
  dismissAction,
  isMutating,
  mutationError,
  viewAllHref,
}: RecommendedActionsView) {
  // Which row's dialog is open, plus its form. Presentation state, so it lives
  // here rather than in the host: the host owns whether a write is in flight
  // (`isMutating`) and what it said (`mutationError`); this owns what the
  // reader has typed and chosen so far.
  const [pending, setPending] = useState<{ action: RecommendedAction; ruleId: string } | null>(
    null,
  );
  const [method, setMethod] = useState<DismissMethod | null>(null);
  const [confirmation, setConfirmation] = useState('');

  const closeDialog = () => {
    setPending(null);
    setMethod(null);
    setConfirmation('');
  };

  const confirmDismiss = () => {
    if (pending === null || method === null) return;
    // Guarded on both paths a host can fail on, and neither is expressible in
    // `dismissAction`'s return type: it may reject, and it may throw
    // synchronously. Each leaves the dialog open over whatever the host put in
    // `mutationError` — the one outcome that must never follow a failure is the
    // dialog closing as though the write had landed.
    //
    // The call itself stays SYNCHRONOUS inside the click handler. Deferring it
    // behind a `Promise.resolve().then(...)` would also catch a synchronous
    // throw, but it starts the host's transition a microtask after the event
    // that caused it, so the work no longer runs as part of the user's own
    // interaction.
    try {
      void dismissAction({ ruleId: pending.ruleId, method, confirmation })
        .then((ok) => {
          // Only a landed write closes it. On a refusal the dialog stays open
          // over the host's `mutationError`, with what was typed still in place.
          if (ok) closeDialog();
        })
        .catch(() => undefined);
    } catch {
      // A host that threw instead of returning a promise. Same outcome as a
      // rejection: the dialog stays open, and nothing here claims a write.
    }
  };

  return (
    <Card className="flex flex-col shadow-sm">
      <CardHeader>
        <CardIcon tone="primary">
          <SparklesIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Recommended actions</CardTitle>
          <CardDescription>
            {/* The scope is named because it is NOT the page's range: this card
                reports what is still open, so a reader whose range selector says
                "last 7 days" is not looking at a seven-day number. */}
            {isLoading ? 'Loading…' : `${String(items.length)} open, prioritized for you`}
          </CardDescription>
        </CardHeading>
        {viewAllHref ? (
          <CardAction>
            <Button asChild variant="ghost" tone="primary" size="sm">
              <a href={viewAllHref}>View all</a>
            </Button>
          </CardAction>
        ) : null}
      </CardHeader>
      <CardContent aria-busy={isLoading}>
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          <div className="flex flex-col gap-3 py-2">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-20 w-full" />
            ))}
          </div>
        ) : items.length === 0 ? (
          // "open", not "right now": an empty card here means nothing is
          // outstanding, which is a different claim from nothing being recent.
          <div className="py-6 text-center text-xs text-text-3">No open findings.</div>
        ) : (
          <>
            {items.map((a, i) => {
              const Icon = RECOMMENDATION_ICON[a.category] ?? AlertOctagonIcon;
              const rule = ruleSubject(a);
              return (
                <div
                  key={a.id}
                  className={cn(
                    'flex gap-3 py-3',
                    i < items.length - 1 && 'border-b border-hairline',
                  )}
                >
                  <span
                    className={cn(
                      'flex size-8 shrink-0 items-center justify-center rounded-lg',
                      TONE_SOFT[SEVERITY_TONE[a.severity]],
                    )}
                  >
                    <Icon aria-hidden focusable={false} className="size-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-text">{a.title}</div>
                    <div className="mt-0.5 text-xs leading-relaxed text-text-2">
                      {a.description}
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      {a.subjects.map((s) => (
                        <Tag key={`${s.type}_${s.id}`}>{s.label}</Tag>
                      ))}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1.5">
                    {a.action.mode === 'apply' ? (
                      <Button
                        variant="solid"
                        tone="primary"
                        size="sm"
                        disabled={isMutating}
                        onClick={() => {
                          applyAction(a.id);
                        }}
                      >
                        {a.action.label}
                      </Button>
                    ) : a.action.href ? (
                      <Button asChild variant="solid" tone="primary" size="sm">
                        <a href={a.action.href}>{a.action.label}</a>
                      </Button>
                    ) : (
                      // `href` is optional; a navigate action without one has nowhere
                      // to go, so show it disabled rather than as a dead link.
                      <Button variant="solid" tone="primary" size="sm" disabled>
                        {a.action.label}
                      </Button>
                    )}
                    {rule === undefined ? null : (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={isMutating}
                        onClick={() => {
                          setPending({ action: a, ruleId: rule.id });
                          setMethod(null);
                          setConfirmation('');
                        }}
                      >
                        Dismiss
                      </Button>
                    )}
                  </div>
                </div>
              );
            })}
          </>
        )}
      </CardContent>

      <Dialog
        open={pending !== null}
        onOpenChange={(open) => {
          // Escape, the overlay and the close button all arrive here. A write in
          // flight is not interruptible by closing the dialog it was started
          // from, so the dismissal would land with nothing on screen saying so.
          if (!open && !isMutating) closeDialog();
        }}
      >
        {pending !== null && (
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Dismiss {pending.ruleId} findings?</DialogTitle>
              <DialogDescription>
                {/* The row's own label, so the dialog names the same set the
                    button was sitting next to rather than a second count
                    derived here. */}
                {ruleSubject(pending.action)?.label ?? pending.ruleId}
              </DialogDescription>
            </DialogHeader>
            <DialogBody className="flex flex-col gap-4">
              <ul className="flex list-disc flex-col gap-1 pl-4 text-xs leading-relaxed text-text-2">
                {dismissConsequences(pending.ruleId).map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>

              <div className="flex flex-col gap-1.5">
                <div
                  id="dismiss-method-label"
                  className="text-label font-semibold uppercase tracking-wider text-text-3"
                >
                  Why are you closing these?
                </div>
                {/* Radio cards, so BOTH descriptions are on screen while the
                    reader chooses. A segmented control with one line of help
                    below it showed only the selected option's, which makes
                    someone pick an answer in order to find out what it means —
                    on a disposition that is recorded against every finding this
                    closes, and that a report later reads as a claim. */}
                <ChoiceGroup
                  name="dismiss-method"
                  labelledBy="dismiss-method-label"
                  choices={DISMISS_METHODS}
                  value={method}
                  onChange={setMethod}
                />
              </div>

              <div className="flex flex-col gap-1.5">
                <div
                  id="dismiss-confirmation-label"
                  className="text-label font-semibold uppercase tracking-wider text-text-3"
                >
                  Confirm
                </div>
                {/* The word is NOT inside the uppercased heading, and that is
                    the whole reason this is two elements. `uppercase` is a CSS
                    transform, so an interpolated `dismiss` rendered as DISMISS
                    while the gate compares exactly — the only instruction
                    saying what to type displayed it in the one case the button
                    refuses, and there was no way out of the dialog but Cancel.
                    Keep the literal in normal-case body text. */}
                <label
                  data-slot="dismiss-confirmation-hint"
                  className="text-xs normal-case text-text-2"
                  htmlFor="dismiss-confirmation"
                >
                  Type{' '}
                  <code className="rounded bg-surface-2 px-1 py-0.5 font-mono text-text">
                    {DISMISS_CONFIRMATION}
                  </code>{' '}
                  to confirm.
                </label>
                <Input
                  id="dismiss-confirmation"
                  data-slot="dismiss-confirmation"
                  value={confirmation}
                  onChange={(e) => {
                    setConfirmation(e.target.value);
                  }}
                  placeholder={DISMISS_CONFIRMATION}
                  className="max-w-56 font-mono"
                />
              </div>

              {/* Rendered INSIDE the dialog: the card's own copy sits behind the
                  overlay, so a refusal shown only there is a refusal nobody
                  reads while the dialog that caused it is still open. */}
              {mutationError !== null && <WidgetError message={mutationError} />}
            </DialogBody>
            <DialogFooter>
              <Button
                variant="ghost"
                size="sm"
                disabled={isMutating}
                onClick={() => {
                  closeDialog();
                }}
              >
                Cancel
              </Button>
              <Button
                variant="solid"
                tone="danger"
                size="sm"
                disabled={!canConfirmDismiss({ confirmation, method, isMutating })}
                onClick={confirmDismiss}
              >
                {isMutating ? 'Dismissing…' : 'Dismiss findings'}
              </Button>
            </DialogFooter>
          </DialogContent>
        )}
      </Dialog>
    </Card>
  );
}
