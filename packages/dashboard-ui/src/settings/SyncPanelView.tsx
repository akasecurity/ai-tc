'use client';
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardHeading,
  CardTitle,
  cn,
  Meter,
  Tag,
} from '@akasecurity/ui-kit';

import { COLORS } from '../lib/colors.ts';
import { relativeTime } from '../lib/relativeTime.ts';

/** One counted lane, as the store reports it. */
export interface SyncKindRow {
  /** The event kind, as the store names it. */
  kind: string;
  /** What to call it to a reader. */
  label: string;
  synced: number;
  /** Still owed: something is going to send these. */
  queued: number;
  /**
   * Terminal on this lane — refused, unsendable, or closed over by a detach.
   * Deliberately one number: a reader deciding what to do next is served by
   * "these will not go", and the store's own surfaces carry the breakdown.
   */
  notSent: number;
  total: number;
}

/**
 * Something this machine holds that the deployment does not receive as rows.
 *
 * A LINE, never a bar, and that is the honest shape rather than a smaller one.
 * A bar implies a denominator and a direction of travel; none of these has
 * either. Findings are re-derived by the deployment from the activity it
 * receives, project data shares are reconciled whole-project so there is no
 * per-item backlog, and inventory is a snapshot keyed by id where the last pass
 * wins. Rendering any of them as "0% synced" would be a false statement about
 * the product, not a rough one.
 */
export interface SyncLocalOnlyLine {
  id: string;
  label: string;
  detail: string;
  /** Rows held locally, when saying how many helps. */
  count?: number;
}

/** How the last pass ended, as the drain recorded it. */
export type SyncLastOutcome = 'ok' | 'unreachable' | 'refused' | 'interrupted';

/**
 * What the panel has to say, before any of it is drawn.
 *
 * A CLOSED SET rather than a bag of optional fields, because these states are
 * mutually exclusive and each has its own sentence. Optional fields would let a
 * caller render a backlog beside "not shared", which is two contradictory
 * statements about one machine.
 *
 * There is deliberately no `standalone` member. A machine that has not attached
 * is not a machine with nothing to sync — it is one this panel has no business
 * describing, so the page renders nothing at all rather than a card full of
 * zeros. Zeros and absence look identical in a bar and mean different things.
 */
export type SyncPanelState =
  | { status: 'not-shared' }
  | { status: 'consent-stale' }
  | { status: 'credential-unusable'; detail: string }
  | { status: 'nothing-recorded' }
  | { status: 'ready'; kinds: readonly SyncKindRow[] };

export interface SyncPanelViewProps {
  state: SyncPanelState;
  /** Where the machine sends, for the header line. */
  deployment: string;
  lastOutcome?: SyncLastOutcome | undefined;
  lastPassAt?: string | undefined;
  /**
   * The instant this render describes. REQUIRED, and not defaulted: a time label
   * is a function of two instants, and a default would read as safe at every
   * call site that forgot to pass one.
   */
  renderedAt: number;
  /** A pass currently holds the lease. */
  running: boolean;
  onSyncNow?: (() => void) | undefined;
  busy?: boolean | undefined;
  /**
   * Why a pass this panel asked for never started. Set only when that is known
   * — the child is detached, so silence here means "not known", never "fine".
   */
  startError?: string | undefined;
  localOnly?: readonly SyncLocalOnlyLine[] | undefined;
}

const OUTCOME_LINE: Record<SyncLastOutcome, string> = {
  ok: 'Last pass sent what was waiting.',
  interrupted: 'Last pass sent some of what was waiting.',
  unreachable: 'Last pass could not reach your deployment. Nothing was lost; it stays queued.',
  refused: 'Your deployment refused this machine’s key. Re-attach to resume.',
};

function count(n: number): string {
  return n.toLocaleString('en-US');
}

function KindRow({ row }: { row: SyncKindRow }) {
  // Green only when everything known has gone. Anything else is in progress,
  // not a warning — a machine mid-drain is working correctly.
  const color = row.queued === 0 && row.notSent === 0 ? COLORS.ok : COLORS.primary;
  return (
    <div className="flex items-center gap-2.5">
      <span className="w-24 shrink-0 truncate text-ui text-text">{row.label}</span>
      <Meter
        value={row.synced}
        max={row.total}
        color={color}
        height={6}
        aria-label={`${row.label}: ${count(row.synced)} of ${count(row.total)} sent`}
      />
      <span className="w-32 shrink-0 text-right text-label tabular-nums text-text-2">
        {count(row.synced)} of {count(row.total)}
      </span>
      {row.notSent > 0 && (
        <span className="w-24 shrink-0 text-right text-label text-text-3">
          {count(row.notSent)} not sent
        </span>
      )}
    </div>
  );
}

/**
 * What this machine has sent to its deployment, and what it still owes.
 *
 * Props-driven and bundler-agnostic like every view here: it fetches nothing and
 * decides nothing about which machine it is describing.
 */
export function SyncPanelView({
  state,
  deployment,
  lastOutcome,
  lastPassAt,
  renderedAt,
  running,
  onSyncNow,
  busy,
  startError,
  localOnly,
}: SyncPanelViewProps) {
  const canSync = state.status === 'ready' || state.status === 'nothing-recorded';
  return (
    <Card>
      <CardHeader>
        <CardHeading>
          <CardTitle>Sync</CardTitle>
          <CardDescription>
            What this machine has sent to {deployment}, and what it still owes.
          </CardDescription>
        </CardHeading>
        {running && <Tag dot={COLORS.primary}>Sending…</Tag>}
        {state.status === 'consent-stale' && <Tag>Paused</Tag>}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {state.status === 'not-shared' && (
          <p className="text-ui text-text-2">
            Existing activity is not shared. Only what this machine records from now on is sent.
          </p>
        )}
        {state.status === 'consent-stale' && (
          <p className="text-ui text-text-2">
            Paused: your grant predates a change to what is sent. Review it above to resume.
          </p>
        )}
        {state.status === 'credential-unusable' && (
          <p className="text-ui text-text-2">{state.detail}</p>
        )}
        {state.status === 'nothing-recorded' && (
          <p className="text-ui text-text-2">Nothing recorded yet.</p>
        )}

        {state.status === 'ready' && state.kinds.map((row) => <KindRow key={row.kind} row={row} />)}

        {lastOutcome !== undefined && (
          <p className={cn('text-label', lastOutcome === 'ok' ? 'text-text-3' : 'text-text-2')}>
            {OUTCOME_LINE[lastOutcome]}
            {lastPassAt !== undefined && <> {relativeTime(lastPassAt, renderedAt)}.</>}
          </p>
        )}

        {startError !== undefined && <p className="text-ui text-text-2">{startError}</p>}

        {canSync && onSyncNow !== undefined && (
          <div className="flex items-center gap-2.5">
            <Button onClick={onSyncNow} disabled={busy === true || running}>
              {running ? 'Sending…' : 'Sync now'}
            </Button>
            {/* Says what the control covers, because it does not cover
                everything the card lists: the lines below are not sent as rows
                at all, and a button beside them would imply otherwise. */}
            <span className="text-label text-text-3">Sends what is queued above.</span>
          </div>
        )}

        {localOnly !== undefined && localOnly.length > 0 && (
          <div className="flex flex-col gap-1.5 border-t border-border pt-3">
            {localOnly.map((line) => (
              <p key={line.id} className="text-label text-text-3">
                <span className="text-text-2">{line.label}</span>
                {line.count !== undefined && <> · {count(line.count)} here</>} — {line.detail}
              </p>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
