import type { DestinationKind, EgressDecision } from '@akasecurity/schema';

/**
 * Handler factories for the Data Shares client shell. Framework-free: each
 * takes its dependencies (state setters, `push`, the Server Action) as plain
 * parameters and returns a closure — the same body a JSX handler would carry
 * inline, just constructed here instead, so it's a plain function call to
 * test rather than a click this suite has no DOM to simulate.
 */

export type PushFn = (opts: { q?: string; dest?: string | null; ep?: string | null }) => void;

export function makeOpenDestHandler(push: PushFn, q: string): (id: string) => void {
  return (id) => {
    push({ q, dest: id });
  };
}

/**
 * Opens a destination reached from the needs-review sheet, switching the table
 * to the tab that destination lives under. Without the switch the table behind
 * the sheet keeps showing whichever kind was last selected, so closing the
 * sheet leaves the just-reviewed destination nowhere on screen.
 *
 * `kindOf` returns undefined when the destination is in no rendered group (the
 * needs-review list is its own server read, so it can name a destination the
 * grouped register's current search filtered out); the tab is left alone then.
 */
export function makeOpenReviewedDestHandler(
  push: PushFn,
  q: string,
  kindOf: (id: string) => DestinationKind | undefined,
  setActiveKind: (kind: DestinationKind) => void,
): (id: string) => void {
  return (id) => {
    const kind = kindOf(id);
    if (kind !== undefined) setActiveKind(kind);
    push({ q, dest: id });
  };
}

export function makeCloseDrawerHandler(
  push: PushFn,
  q: string,
  setDecisionError: (message: string | null) => void,
): () => void {
  return () => {
    setDecisionError(null);
    push({ q });
  };
}

export function makeReviewOpenHandler(setReviewOpen: (open: boolean) => void): () => void {
  return () => {
    setReviewOpen(true);
  };
}

export function makeTabsValueChangeHandler(
  setActiveKind: (kind: DestinationKind) => void,
): (kind: string) => void {
  return (kind) => {
    setActiveKind(kind as DestinationKind);
  };
}

export function makeExpandToggleHandler(
  setExpanded: (updater: (m: Record<string, boolean>) => Record<string, boolean>) => void,
): (id: string) => void {
  return (id) => {
    setExpanded((m) => ({ ...m, [id]: !m[id] }));
  };
}

export function makeOpenEndpointHandler(
  push: PushFn,
  q: string,
): (id: string, endpointId: string) => void {
  return (id, endpointId) => {
    push({ q, dest: id, ep: endpointId });
  };
}

export function makeOnPickHandler(
  push: PushFn,
  q: string,
  destinationId: string,
): (endpointId: string) => void {
  return (endpointId) => {
    push({ q, dest: destinationId, ep: endpointId });
  };
}

export function makeOnBackHandler(push: PushFn, q: string, destinationId: string): () => void {
  return () => {
    push({ q, dest: destinationId });
  };
}

/**
 * The needs-review/detail Sheet's close policy.
 *
 * `closeDrawer` runs on every dismissal, not just when a detail is showing. It
 * clears `dest` from the URL, which is a no-op when none is set — but when a
 * "Review" navigation is still in flight it supersedes that push, so the
 * arriving `dest` cannot re-open the sheet on the destination the user just
 * dismissed. Branching on `drawerOpen` alone cannot cover that case: it is
 * captured at render time and still reads false while the push is in flight.
 *
 * `drawerOpen` still decides whether the review LIST survives the dismissal —
 * closing a detail reached from the list falls back to it ("back to list"),
 * while dismissing the list itself closes the sheet outright.
 */
export function makeReviewSheetOpenChangeHandler(
  drawerOpen: boolean,
  closeDrawer: () => void,
  setReviewOpen: (open: boolean) => void,
): (open: boolean) => void {
  return (open) => {
    if (open) return;
    if (!drawerOpen) setReviewOpen(false);
    closeDrawer();
  };
}

export interface SetDecisionDeps {
  isSettingDecision: boolean;
  destinationId: string;
  setDecisionError: (message: string | null) => void;
  startTransition: (callback: () => void | Promise<void>) => void;
  setEgressDecision: (destinationId: string, decision: EgressDecision | null) => Promise<boolean>;
}

/**
 * Applies an egress-decision write and surfaces a failure instead of
 * silently keeping the stale toggle — this is a security-posture control, so
 * a silent no-op is the worst mode.
 */
export function makeSetDecisionHandler(
  deps: SetDecisionDeps,
): (decision: EgressDecision | null) => void {
  return (decision) => {
    if (deps.isSettingDecision) return;
    deps.setDecisionError(null);
    deps.startTransition(async () => {
      try {
        const ok = await deps.setEgressDecision(deps.destinationId, decision);
        if (!ok) {
          deps.setDecisionError('This destination no longer exists — reload to refresh the list.');
        }
      } catch {
        deps.setDecisionError('Could not update the egress decision. Please try again.');
      }
    });
  };
}
