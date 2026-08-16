import { describe, expect, it } from 'vitest';

import type { DataGateway, LocalStoreMaintenance } from '../src/data-gateway.ts';
import { hasLocalStoreMaintenance } from '../src/data-gateway.ts';

const maintenance: LocalStoreMaintenance = {
  sweepTerminalExceptions: () => Promise.resolve(0),
  capWarnEraEnforcement: () => ({ capped: 0 }),
  recordProjectFiles: () => Promise.resolve(),
  reconcileWorktreeProjects: () => Promise.resolve(),
  staleBinaryNotice: () => null,
};

function gatewayWith(extra: object): DataGateway {
  return { close: () => Promise.resolve(), ...extra } as unknown as DataGateway;
}

describe('hasLocalStoreMaintenance', () => {
  it('accepts a gateway offering all five members', () => {
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
