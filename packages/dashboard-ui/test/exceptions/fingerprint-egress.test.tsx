// Pins the egress rule for the exceptions surfaces: the keyed valueFingerprint
// is a correlation key and must never reach a view layer or the browser (the
// rule PointerDescriptor states in @akasecurity/schema). Two layers of pin:
//   - compile-time: every view's prop contract is a fingerprint-free
//     descriptor shape, so a literal carrying the field is a type error;
//   - render-time: even when a caller holds a full store row (assignable to
//     the descriptor, so the extra field can ride through a non-literal), no
//     fragment of the fingerprint may appear in the server-rendered markup.
// The two dialogs mount their content through a Radix portal, which renders
// nothing under react-dom/server — an absence assertion on their empty markup
// would pass vacuously, so they are covered by the compile-time pins only.
import type { BlockedDetection, DetectionException } from '@akasecurity/schema';
import { toBlockedDetectionDescriptor, toExceptionDescriptor } from '@akasecurity/schema';
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

// Full store rows, fingerprint included — the shape a careless caller could
// still hand to a view, since the descriptor accepts it structurally.
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
      <ExceptionDetailView exception={exceptionRow} onRevoke={vi.fn()} />,
    );
    // Positive control first — an empty render passes every absence check vacuously.
    expect(markup).toContain(exceptionRow.id.slice(0, 8));
    expect(markup).toContain(exceptionRow.maskedValue);
    expect(markup).toContain(exceptionRow.justification);
    expectNoFingerprintEcho(markup);
  });

  it('ExceptionsTableView renders full grant rows without any fingerprint fragment', () => {
    const markup = renderToStaticMarkup(
      <ExceptionsTableView items={[exceptionRow]} includeTerminal={false} onSelect={vi.fn()} />,
    );
    expect(markup).toContain(exceptionRow.id.slice(0, 8));
    expect(markup).toContain(exceptionRow.maskedValue);
    expectNoFingerprintEcho(markup);
  });

  it('BlockedLedgerView renders full ledger rows without any fingerprint fragment', () => {
    const markup = renderToStaticMarkup(
      <BlockedLedgerView
        items={[blockedRow]}
        onApprove={vi.fn()}
        blockedWindow="30m"
        onBlockedWindowChange={vi.fn()}
        keyState={{ status: 'present', version: blockedRow.keyVersion }}
      />,
    );
    expect(markup).toContain(blockedRow.reference);
    expect(markup).toContain(blockedRow.maskedValue);
    expectNoFingerprintEcho(markup);
  });

  it('every view prop contract rejects a literal that carries the fingerprint', () => {
    const detail: ExceptionDetailViewProps['exception'] = {
      ...toExceptionDescriptor(exceptionRow),
      // @ts-expect-error -- the detail view takes the fingerprint-free descriptor
      valueFingerprint: FINGERPRINT,
    };
    const tableItem: ExceptionsTableViewProps['items'][number] = {
      ...toExceptionDescriptor(exceptionRow),
      // @ts-expect-error -- the table view takes the fingerprint-free descriptor
      valueFingerprint: FINGERPRINT,
    };
    const rotateItem: RotateKeyDialogProps['activePermanent'][number] = {
      ...toExceptionDescriptor(exceptionRow),
      // @ts-expect-error -- the rotate dialog takes the fingerprint-free descriptor
      valueFingerprint: FINGERPRINT,
    };
    const ledgerItem: BlockedLedgerViewProps['items'][number] = {
      ...toBlockedDetectionDescriptor(blockedRow),
      // @ts-expect-error -- the ledger view takes the fingerprint-free descriptor
      valueFingerprint: FINGERPRINT,
    };
    const approveEntry: ApproveExceptionDialogProps['entry'] = {
      ...toBlockedDetectionDescriptor(blockedRow),
      // @ts-expect-error -- the approve dialog takes the fingerprint-free descriptor
      valueFingerprint: FINGERPRINT,
    };
    for (const pinned of [detail, tableItem, rotateItem]) {
      expect(pinned.id).toBe(exceptionRow.id);
    }
    for (const pinned of [ledgerItem, approveEntry]) {
      expect(pinned?.reference).toBe(blockedRow.reference);
    }
  });
});
