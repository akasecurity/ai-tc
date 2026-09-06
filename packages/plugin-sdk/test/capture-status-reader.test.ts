import { describe, expect, it } from 'vitest';

import type { CaptureStatusReader, DataGateway } from '../src/data-gateway.ts';
import { offersCaptureStatusReader } from '../src/data-gateway.ts';

const reader: CaptureStatusReader = {
  readCaptureStatuses: () => Promise.resolve([]),
};

function gatewayWith(extra: object): DataGateway {
  return { close: () => Promise.resolve(), ...extra } as unknown as DataGateway;
}

describe('offersCaptureStatusReader', () => {
  it('accepts a gateway supplying the member', () => {
    expect(offersCaptureStatusReader(gatewayWith(reader))).toBe(true);
  });

  it('rejects a gateway that does not supply it', () => {
    expect(offersCaptureStatusReader(gatewayWith({}))).toBe(false);
  });

  it('rejects a member that is present but not callable', () => {
    expect(offersCaptureStatusReader(gatewayWith({ readCaptureStatuses: true }))).toBe(false);
  });

  it('accepts a wrapper that DELEGATES the member, not just a subclass', () => {
    const delegating = {
      readCaptureStatuses: (...args: unknown[]) =>
        (reader.readCaptureStatuses as (...a: unknown[]) => unknown)(...args),
    };
    expect(offersCaptureStatusReader(gatewayWith(delegating))).toBe(true);
  });
});
