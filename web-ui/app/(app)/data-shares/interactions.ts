import type { DestinationKind, EgressDecision } from '@akasecurity/schema';
import type { ChangeEvent } from 'react';

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

export function makeSearchChangeHandler(
  setQuery: (value: string) => void,
): (e: ChangeEvent<HTMLInputElement>) => void {
  return (e) => {
    setQuery(e.target.value);
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
 * The needs-review/detail Sheet's close policy: closing while a detail is
 * open just clears `dest`, which falls back to the review list if that sheet
 * is still logically open (reviewOpen) — see DataSharesClient's own comment
 * on the merged Sheet for why. Closing while the list itself is showing
 * closes the whole sheet.
 */
export function makeReviewSheetOpenChangeHandler(
  drawerOpen: boolean,
  closeDrawer: () => void,
  setReviewOpen: (open: boolean) => void,
): (open: boolean) => void {
  return (open) => {
    if (open) return;
    if (drawerOpen) {
      closeDrawer();
    } else {
      setReviewOpen(false);
    }
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
