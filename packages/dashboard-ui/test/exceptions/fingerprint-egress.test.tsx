// Pins the egress rule for the exceptions surfaces: the keyed valueFingerprint
// is a correlation key and must never reach a view layer or the browser (the
// rule PointerDescriptor states in @akasecurity/schema). Two layers of pin:
//   - compile-time: every view's prop contract is a fingerprint-free
//     descriptor, and those descriptors EXCLUDE the field rather than merely
//     omitting it, so an unprojected store row is unassignable — dropping a
//     projection call at a server boundary fails typecheck rather than
//     silently putting the fingerprint back in the RSC payload;
//   - render-time: no view reads the field even when one is forced past the
//     type (below), so the exclusion is not the only thing standing between
//     the digest and the markup.
// The two dialogs mount their content through a Radix portal, which renders
// nothing under react-dom/server — an absence assertion on their empty markup
// would pass vacuously, so they are covered by the compile-time pins only.
import type {
  BlockedDetection,
  BlockedDetectionDescriptor,
  DetectionException,
  ExceptionDescriptor,
} from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ApproveExceptionDialogProps } from '../../src/exceptions/ApproveExceptionDialog.tsx';
import {
  BlockedLedgerView,
  type BlockedLedgerViewProps,
} from '../../src/exceptions/BlockedLedgerView.tsx';
import {
  ExceptionDetailView,
  type ExceptionDetailViewProps,
} from '../../src/exceptions/ExceptionDetailView.tsx';
import {
  ExceptionsTableView,
  type ExceptionsTableViewProps,
} from '../../src/exceptions/ExceptionsTableView.tsx';
import type { RotateKeyDialogProps } from '../../src/exceptions/RotateKeyDialog.tsx';

// Distinctive hex so a fragment of it in markup is an echo, not a coincidence;
// no other fixture value below shares a 6-character window with it.
const FINGERPRINT = 'ba5eba11deadbea7f01dab1ecafed00dfeedface8badf00dca11ab1e0ddba11e';

// Full store rows, fingerprint included — what a server boundary holds before
// it projects.
const exceptionRow: DetectionException = {
  id: '7d9f7a4e-1111-4222-8333-444455556666',
  ruleId: 'secrets/aws-access-key',
  category: 'secret',
  valueFingerprint: FINGERPRINT,
  keyVersion: 3,
  maskedValue: 'AKIA****************',
  capability: 'suppress',
  scope: 'permanent',
  expiresAt: null,
  maxUses: null,
  useCount: 2,
  lastUsedAt: '2026-07-01T00:00:00.000Z',
  justification: 'sandbox key used in integration-test fixtures',
  conditions: null,
  createdBy: 'tester',
  createdVia: 'web-add',
  createdAt: '2026-06-30T00:00:00.000Z',
  updatedAt: '2026-07-01T00:00:00.000Z',
  revokedAt: null,
  revokedBy: null,
  revokeReason: null,
};

const blockedRow: BlockedDetection = {
  reference: 'blk-1234',
  ruleId: 'secrets/aws-access-key',
  category: 'secret',
  valueFingerprint: FINGERPRINT,
  keyVersion: 3,
  maskedValue: 'AKIA****************',
  sessionId: null,
  repo: 'github.com/acme/api',
  blockedAt: '2026-07-03T11:59:00.000Z',
};

// Force a full row past the descriptor exclusion, so the render cases below
// can ask the question the exclusion now prevents a caller from asking: if one
// DID arrive, would any view put it on screen? A cast is the only way in, and
// that is the point — outside this file the type refuses it.
const asExceptionDescriptor = (row: DetectionException): ExceptionDescriptor =>
  row as unknown as ExceptionDescriptor;
const asBlockedDescriptor = (row: BlockedDetection): BlockedDetectionDescriptor =>
  row as unknown as BlockedDetectionDescriptor;

// A truncated echo is still an echo — a fingerprint prefix is as stable a
// correlation key as the whole digest — so assert window-by-window rather
// than on the full value.
function expectNoFingerprintEcho(markup: string): void {
  for (let start = 0; start + 6 <= FINGERPRINT.length; start += 1) {
    expect(markup).not.toContain(FINGERPRINT.slice(start, start + 6));
  }
}

describe('exceptions views never render the valueFingerprint', () => {
  it('ExceptionDetailView renders a full grant row without any fingerprint fragment', () => {
    const markup = renderToStaticMarkup(
      <ExceptionDetailView exception={asExceptionDescriptor(exceptionRow)} onRevoke={vi.fn()} />,
    );
    // Positive control first — an empty render passes every absence check vacuously.
    expect(markup).toContain(exceptionRow.id.slice(0, 8));
    expect(markup).toContain(exceptionRow.maskedValue);
    expect(markup).toContain(exceptionRow.justification);
    expectNoFingerprintEcho(markup);
  });

  it('ExceptionsTableView renders full grant rows without any fingerprint fragment', () => {
    const markup = renderToStaticMarkup(
      <ExceptionsTableView
        items={[asExceptionDescriptor(exceptionRow)]}
        includeTerminal={false}
        onSelect={vi.fn()}
      />,
    );
    expect(markup).toContain(exceptionRow.id.slice(0, 8));
    expect(markup).toContain(exceptionRow.maskedValue);
    expectNoFingerprintEcho(markup);
  });

  it('BlockedLedgerView renders full ledger rows without any fingerprint fragment', () => {
    const markup = renderToStaticMarkup(
      <BlockedLedgerView
        items={[asBlockedDescriptor(blockedRow)]}
        onApprove={vi.fn()}
        blockedWindow="30m"
        onBlockedWindowChange={vi.fn()}
        // Approvable, so the row renders its full content — which is what
        // makes the fingerprint-absence assertion below meaningful.
        blockReason={() => null}
      />,
    );
    expect(markup).toContain(blockedRow.reference);
    expect(markup).toContain(blockedRow.maskedValue);
    expectNoFingerprintEcho(markup);
  });

  it('BlockedLedgerView renders a host-supplied block reason without any fingerprint fragment', () => {
    // `blockReason` is the one new way arbitrary text reaches this view, and
    // the case above short-circuits it: `() => null` renders neither the reason
    // line nor the Approve description tied to it. A host composing that
    // wording from the store row is precisely how the fingerprint would get
    // here, so the guard has to see the path rendered rather than beside it.
    const markup = renderToStaticMarkup(
      <BlockedLedgerView
        items={[asBlockedDescriptor(blockedRow)]}
        onApprove={vi.fn()}
        blockedWindow="30m"
        onBlockedWindowChange={vi.fn()}
        blockReason={() => 'Recorded under an older key.'}
      />,
    );
    expect(markup).toContain(blockedRow.reference);
    expect(markup).toContain('Recorded under an older key.');
    expectNoFingerprintEcho(markup);
  });

  it('every view prop contract rejects an unprojected store row', () => {
    // Not a literal-only pin: these are `declare`-equivalent typed values, so
    // excess-property checking is not what refuses them — the descriptor's
    // `valueFingerprint?: never` is. This is the guard that makes dropping a
    // projection call at a server boundary a build failure.
    // @ts-expect-error -- the detail view takes the fingerprint-free descriptor
    const detail: ExceptionDetailViewProps['exception'] = exceptionRow;
    // @ts-expect-error -- the table view takes the fingerprint-free descriptor
    const tableItem: ExceptionsTableViewProps['items'][number] = exceptionRow;
    // @ts-expect-error -- the rotate dialog takes the fingerprint-free descriptor
    const rotateItem: RotateKeyDialogProps['activePermanent'][number] = exceptionRow;
    // @ts-expect-error -- the ledger view takes the fingerprint-free descriptor
    const ledgerItem: BlockedLedgerViewProps['items'][number] = blockedRow;
    // @ts-expect-error -- the approve dialog takes the fingerprint-free descriptor
    const approveEntry: ApproveExceptionDialogProps['entry'] = blockedRow;

    for (const pinned of [detail, tableItem, rotateItem]) {
      expect(pinned.id).toBe(exceptionRow.id);
    }
    for (const pinned of [ledgerItem, approveEntry]) {
      expect(pinned?.reference).toBe(blockedRow.reference);
    }
  });
});
