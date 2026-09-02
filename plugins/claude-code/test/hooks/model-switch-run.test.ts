import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { readSessionModel, recordSessionModel } from '@akasecurity/plugin-sdk';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { handleProhibitedTurn, refuseProhibitedTurn } from '../../src/hooks/model-guard.ts';
import { runPostModelSwitch, runPreModelSwitch } from '../../src/hooks/model-switch-run.ts';

// One temp root for the file, with a cheap subdirectory per test. These cases
// need an isolated marker file rather than an isolated filesystem, and a
// recursive remove per test is slow enough on Windows to be worth not paying.
let root: string;
let dir: string;
let n = 0;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-switch-run-'));
});

beforeEach(() => {
  n += 1;
  dir = join(root, `t${String(n)}`);
  mkdirSync(dir, { recursive: true });
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

const config = (): PluginConfig => ({ dataDir: dir }) as unknown as PluginConfig;

/** A gateway stubbed down to the one read these paths perform. */
function gatewayWith(
  prohibited: string[] | undefined,
  onClose = vi.fn(),
  recordAuditEvent: (event: unknown) => Promise<void> = () => Promise.resolve(),
): DataGateway {
  return {
    getPolicyBundle: () =>
      Promise.resolve({ prohibitedModels: prohibited } as unknown as Awaited<
        ReturnType<DataGateway['getPolicyBundle']>
      >),
    recordAuditEvent,
    close: onClose,
  } as unknown as DataGateway;
}

/** One recorded audit row, in the shape these assertions read. */
interface RecordedEvent {
  eventType: string;
  attributes: Record<string, unknown>;
}

/**
 * The one row a refusal is expected to record.
 *
 * Narrows by construction rather than by an assertion — both `!` and `as` are
 * refused here — and states the cardinality while it is at it: two rows for one
 * refusal would be a defect these assertions would otherwise read straight past.
 */
function onlyEvent(events: readonly RecordedEvent[]): RecordedEvent {
  const [first, ...rest] = events;
  if (first === undefined || rest.length > 0) {
    throw new Error(`expected exactly one recorded event, got ${String(events.length)}`);
  }
  return first;
}

/** A recorder plus the rows it captured, typed so no mock tuple is indexed. */
function recorder(): {
  fn: (event: unknown) => Promise<void>;
  events: RecordedEvent[];
} {
  const events: RecordedEvent[] = [];
  return {
    fn: (event: unknown) => {
      events.push(event as RecordedEvent);
      return Promise.resolve();
    },
    events,
  };
}

describe('runPreModelSwitch', () => {
  it('refuses the switch and records NOTHING when the target is prohibited', () => {
    // A refused switch never happened, so recording its target would make the
    // next turn enforce against a model the session is not running.
    const emit = vi.fn(() => Promise.resolve());
    return runPreModelSwitch({}, 'claude-opus-5', 's1', {
      config: config(),
      openGateway: () => gatewayWith(['claude-opus-5']),
      emit,
      warnIfStoreRedirected: vi.fn(),
    }).then((refused) => {
      expect(refused).toBe(true);
      expect(emit).toHaveBeenCalledTimes(1);
      expect(readSessionModel(dir, 's1')).toBeUndefined();
    });
  });

  it('allows an approved switch, emits nothing, and records the new model', async () => {
    const emit = vi.fn(() => Promise.resolve());
    const refused = await runPreModelSwitch({}, 'claude-sonnet-4-5', 's1', {
      config: config(),
      openGateway: () => gatewayWith(['claude-opus-5']),
      emit,
      warnIfStoreRedirected: vi.fn(),
    });
    expect(refused).toBe(false);
    expect(emit).not.toHaveBeenCalled();
    expect(readSessionModel(dir, 's1')).toBe('claude-sonnet-4-5');
  });

  it('allows — silently — when the store cannot be opened', async () => {
    // Fail-open: no store means no bundle means no prohibition to enforce, and
    // this hook deliberately does not explain store health.
    const emit = vi.fn(() => Promise.resolve());
    const refused = await runPreModelSwitch({}, 'claude-opus-5', 's1', {
      config: config(),
      openGateway: () => null,
      emit,
      warnIfStoreRedirected: vi.fn(),
    });
    expect(refused).toBe(false);
    expect(emit).not.toHaveBeenCalled();
  });

  it('closes the gateway on both the refusal and the allow path', async () => {
    for (const [target, label] of [
      ['claude-opus-5', 'refusal'],
      ['claude-sonnet-4-5', 'allow'],
    ] as const) {
      const close = vi.fn(() => Promise.resolve());
      await runPreModelSwitch({}, target, 's1', {
        config: config(),
        openGateway: () => gatewayWith(['claude-opus-5'], close),
        emit: vi.fn(() => Promise.resolve()),
        warnIfStoreRedirected: vi.fn(),
      });
      expect(close, `gateway left open on the ${label} path`).toHaveBeenCalledTimes(1);
    }
  });

  it('surfaces a redirected home before deciding', async () => {
    const warn = vi.fn();
    await runPreModelSwitch({}, 'claude-opus-5', 's1', {
      config: config(),
      openGateway: () => gatewayWith([]),
      emit: vi.fn(() => Promise.resolve()),
      warnIfStoreRedirected: warn,
    });
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe('runPreModelSwitch records the refusal', () => {
  it('writes a model_refusal naming the model and the switch seam', async () => {
    const rec = recorder();
    await runPreModelSwitch({}, 'claude-opus-5', 's1', {
      config: config(),
      openGateway: () => gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
      emit: vi.fn(() => Promise.resolve()),
      warnIfStoreRedirected: vi.fn(),
      newId: () => 'evt-1',
      now: () => new Date('2026-09-02T10:30:00.000Z'),
    });
    const event = onlyEvent(rec.events);
    expect(event.eventType).toBe('model_refusal');
    expect(event.attributes.model).toBe('claude-opus-5');
    expect(event.attributes.refusal_seam).toBe('switch');
  });

  it('records nothing when the switch is ALLOWED', async () => {
    const rec = recorder();
    await runPreModelSwitch({}, 'claude-sonnet-4-5', 's1', {
      config: config(),
      openGateway: () => gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
      emit: vi.fn(() => Promise.resolve()),
      warnIfStoreRedirected: vi.fn(),
    });
    expect(rec.events).toHaveLength(0);
  });

  it('still refuses when the refusal cannot be recorded', async () => {
    // The failure this must never have: a write that throws reaching the entry's
    // outer catch would turn a deny into a fail-open allow, leaving the session
    // LESS governed than before the audit trail existed.
    const emit = vi.fn(() => Promise.resolve());
    const refused = await runPreModelSwitch({}, 'claude-opus-5', 's1', {
      config: config(),
      openGateway: () =>
        gatewayWith(
          ['claude-opus-5'],
          vi.fn(),
          vi.fn(() => Promise.reject(new Error('store gone'))),
        ),
      emit,
      warnIfStoreRedirected: vi.fn(),
    });
    expect(refused).toBe(true);
    expect(emit).toHaveBeenCalledTimes(1);
  });
});

describe('runPostModelSwitch', () => {
  it('records the model the harness switched to', () => {
    runPostModelSwitch('s1', 'claude-opus-5', {
      config: config(),
      warnIfStoreRedirected: vi.fn(),
    });
    expect(readSessionModel(dir, 's1')).toBe('claude-opus-5');
  });

  it('records nothing when the harness named no model', () => {
    runPostModelSwitch('s1', undefined, { config: config(), warnIfStoreRedirected: vi.fn() });
    expect(readSessionModel(dir, 's1')).toBeUndefined();
  });
});

describe('refuseProhibitedTurn', () => {
  it('refuses a turn on a model the marker says is prohibited', async () => {
    recordSessionModel(dir, 's1', 'claude-opus-5');
    const out = await refuseProhibitedTurn(gatewayWith(['claude-opus-5']), dir, 's1', undefined);
    expect(out?.decision.decision).toBe('block');
    expect(out?.decision.reason).toContain('claude-opus-5');
    // The model rides back with the verdict so the audit row and the message
    // the user sees can never disagree about which model was refused.
    expect(out?.model).toBe('claude-opus-5');
  });

  it('falls back to the transcript when no marker covers the session', async () => {
    const transcript = join(dir, 't.jsonl');
    writeFileSync(
      transcript,
      JSON.stringify({ type: 'assistant', message: { model: 'claude-opus-5' } }),
    );
    expect(
      await refuseProhibitedTurn(gatewayWith(['claude-opus-5']), dir, 's1', transcript),
    ).not.toBeNull();
  });

  it('never reads the transcript when the bundle prohibits nothing', async () => {
    // The ordering that keeps an unenforced tenant off the transcript entirely:
    // a bundle with no list short-circuits before the model is resolved.
    recordSessionModel(dir, 's1', 'claude-opus-5');
    expect(await refuseProhibitedTurn(gatewayWith([]), dir, 's1', undefined)).toBeNull();
    expect(await refuseProhibitedTurn(gatewayWith(undefined), dir, 's1', undefined)).toBeNull();
  });

  it('allows when the bundle cannot be read at all', async () => {
    const broken = {
      getPolicyBundle: () => Promise.reject(new Error('store gone')),
    } as unknown as DataGateway;
    recordSessionModel(dir, 's1', 'claude-opus-5');
    expect(await refuseProhibitedTurn(broken, dir, 's1', undefined)).toBeNull();
  });

  it('allows when the model cannot be resolved from either source', async () => {
    expect(
      await refuseProhibitedTurn(gatewayWith(['claude-opus-5']), dir, 's1', undefined),
    ).toBeNull();
  });
});

describe('handleProhibitedTurn', () => {
  it('closes the gateway and emits the block, then tells the caller to stop', async () => {
    recordSessionModel(dir, 's1', 'claude-opus-5');
    const close = vi.fn(() => Promise.resolve());
    const emitted: { decision: 'block'; reason: string }[] = [];
    const emit = (output: { decision: 'block'; reason: string }): Promise<void> => {
      emitted.push(output);
      return Promise.resolve();
    };
    const stop = await handleProhibitedTurn(
      gatewayWith(['claude-opus-5'], close),
      dir,
      's1',
      undefined,
      emit,
    );
    expect(stop).toBe(true);
    expect(close).toHaveBeenCalledTimes(1);
    expect(emitted).toHaveLength(1);
    expect(emitted[0]?.decision).toBe('block');
    expect(emitted[0]?.reason).toContain('claude-opus-5');
  });

  it('leaves the gateway OPEN and emits nothing when the turn is allowed', async () => {
    // The caller goes on to build a runtime over this gateway and closes it in
    // its own `finally`; closing here would pull it out from under the scan.
    const close = vi.fn(() => Promise.resolve());
    const emit = vi.fn(() => Promise.resolve());
    const stop = await handleProhibitedTurn(gatewayWith([], close), dir, 's1', undefined, emit);
    expect(stop).toBe(false);
    expect(close).not.toHaveBeenCalled();
    expect(emit).not.toHaveBeenCalled();
  });
});

describe('handleProhibitedTurn records the refusal', () => {
  it('writes a model_refusal naming the TURN seam', async () => {
    recordSessionModel(dir, 's1', 'claude-opus-5');
    const rec = recorder();
    await handleProhibitedTurn(
      gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
      dir,
      's1',
      undefined,
      () => Promise.resolve(),
    );
    const event = onlyEvent(rec.events);
    expect(event.eventType).toBe('model_refusal');
    expect(event.attributes.model).toBe('claude-opus-5');
    // The seam is what separates this from the switch refusal in the same
    // session — an operator asking "was it prevented, or contained?" reads it.
    expect(event.attributes.refusal_seam).toBe('turn');
  });

  it('still refuses when the refusal cannot be recorded', async () => {
    // A write that throws must not reach the entry's outer catch, which would
    // turn the block into a fail-open allow.
    recordSessionModel(dir, 's1', 'claude-opus-5');
    const emitted: unknown[] = [];
    const stop = await handleProhibitedTurn(
      gatewayWith(['claude-opus-5'], vi.fn(), () => Promise.reject(new Error('store gone'))),
      dir,
      's1',
      undefined,
      (output) => {
        emitted.push(output);
        return Promise.resolve();
      },
    );
    expect(stop).toBe(true);
    expect(emitted).toHaveLength(1);
  });

  it('records nothing when the turn is allowed', async () => {
    const rec = recorder();
    await handleProhibitedTurn(gatewayWith([], vi.fn(), rec.fn), dir, 's1', undefined, () =>
      Promise.resolve(),
    );
    expect(rec.events).toHaveLength(0);
  });
});
