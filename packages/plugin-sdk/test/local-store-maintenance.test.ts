import { describe, expect, it } from 'vitest';

import type { DataGateway, LocalStoreMaintenance } from '../src/data-gateway.ts';
import { hasLocalStoreMaintenance, offersMaintenance } from '../src/data-gateway.ts';

const maintenance: LocalStoreMaintenance = {
  sweepTerminalExceptions: () => Promise.resolve(0),
  capWarnEraEnforcement: () => ({ capped: 0 }),
  recordProjectFiles: () => Promise.resolve(),
  reconcileWorktreeProjects: () => Promise.resolve(),
  staleBinaryNotice: () => null,
  markCaptureDelivered: () => undefined,
  markCaptureOwed: () => undefined,
  markAuditEventsDelivered: () => undefined,
};

function gatewayWith(extra: object): DataGateway {
  return { close: () => Promise.resolve(), ...extra } as unknown as DataGateway;
}

const MEMBERS = Object.keys(maintenance) as (keyof LocalStoreMaintenance)[];

describe('offersMaintenance', () => {
  it('accepts each member a gateway supplies', () => {
    const gateway = gatewayWith(maintenance);
    for (const member of MEMBERS) expect(offersMaintenance(gateway, member)).toBe(true);
  });

  it('rejects ONLY the omitted member, leaving the others offered', () => {
    // The property the session-start gate rests on: one absent member must not
    // withdraw the others. An all-or-nothing predicate would answer false
    // for every name here, so this is what separates the two designs.
    for (const omitted of MEMBERS) {
      const partial = Object.fromEntries(
        Object.entries(maintenance).filter(([name]) => name !== omitted),
      );
      const gateway = gatewayWith(partial);
      expect(offersMaintenance(gateway, omitted)).toBe(false);
      for (const other of MEMBERS.filter((name) => name !== omitted)) {
        expect(offersMaintenance(gateway, other)).toBe(true);
      }
    }
  });

  it('rejects a member that is present but not callable', () => {
    const gateway = gatewayWith({ ...maintenance, sweepTerminalExceptions: true });
    expect(offersMaintenance(gateway, 'sweepTerminalExceptions')).toBe(false);
    expect(offersMaintenance(gateway, 'staleBinaryNotice')).toBe(true);
  });

  it('rejects every member of a bare gateway', () => {
    const gateway = gatewayWith({});
    for (const member of MEMBERS) expect(offersMaintenance(gateway, member)).toBe(false);
  });
});

describe('hasLocalStoreMaintenance', () => {
  it('accepts a gateway offering every member', () => {
    expect(hasLocalStoreMaintenance(gatewayWith(maintenance))).toBe(true);
  });

  it('accepts a plain object that DELEGATES the members, not just a subclass', () => {
    // The point of a structural guard: a wrapper that forwards to an inner
    // gateway qualifies, and no prototype chain is consulted.
    const delegating = Object.fromEntries(
      Object.entries(maintenance).map(([name, fn]) => [
        name,
        (...args: unknown[]) => (fn as (...a: unknown[]) => unknown)(...args),
      ]),
    );
    expect(hasLocalStoreMaintenance(gatewayWith(delegating))).toBe(true);
  });

  it('rejects a gateway missing any one member', () => {
    for (const omitted of Object.keys(maintenance)) {
      const partial = Object.fromEntries(
        Object.entries(maintenance).filter(([name]) => name !== omitted),
      );
      expect(hasLocalStoreMaintenance(gatewayWith(partial))).toBe(false);
    }
  });

  it('rejects a gateway whose members are present but not callable', () => {
    const notFunctions = Object.fromEntries(Object.keys(maintenance).map((name) => [name, true]));
    expect(hasLocalStoreMaintenance(gatewayWith(notFunctions))).toBe(false);
  });

  it('rejects a bare gateway', () => {
    expect(hasLocalStoreMaintenance(gatewayWith({}))).toBe(false);
  });
});
