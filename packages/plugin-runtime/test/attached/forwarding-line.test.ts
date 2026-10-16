import { describe, expect, it } from 'vitest';

import type { ForwardingScope } from '../../src/attached/forwarding-line.ts';
import { forwardingLine } from '../../src/attached/forwarding-line.ts';

// The line is read off whatever gateway the session start wrote through, so
// each case hands it a gateway that answers `forwardingScope` one way. The
// attached gateway's own answers are pinned in gateway.test.ts, and the two are
// driven together, from real credential files, in
// session-start-scoped-credential.test.ts.

const LOCAL_ONLY =
  'AKA: local-only (not enrolled); work in an enrolled repository is still forwarded';
const WORK_KEY = 'github.com/acme/work';

function answering(scope: ForwardingScope | null): object {
  return { forwardingScope: () => scope };
}

describe('forwardingLine', () => {
  it('says everything forwards on a machine attachment', () => {
    expect(forwardingLine(answering({ deploymentName: 'Acme', mode: 'machine' }), 's1')).toBe(
      'AKA: forwarding everything to Acme (machine-wide)',
    );
  });

  it('names the stored root key when the gateway forwards the root', () => {
    const scope: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: WORK_KEY,
      rootForwards: true,
    };
    expect(forwardingLine(answering(scope), 's1')).toBe(`AKA: forwarding to Acme (${WORK_KEY})`);
  });

  // The gateway's verdict decides, not the key's presence: a keyed root the
  // gateway holds local is local-only.
  it('says local-only when the gateway holds a keyed root local', () => {
    const scope: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: 'github.com/me/personal',
      rootForwards: false,
    };
    expect(forwardingLine(answering(scope), 's1')).toBe(LOCAL_ONLY);
  });

  it('says local-only when the store holds no key for the root', () => {
    const scope: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: undefined,
      rootForwards: false,
    };
    expect(forwardingLine(answering(scope), 's1')).toBe(LOCAL_ONLY);
  });

  it('strips control characters from the stored key', () => {
    const scope: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: 'github.com/acme/\u001b[31mwork',
      rootForwards: true,
    };
    expect(forwardingLine(answering(scope), 's1')).toBe(
      'AKA: forwarding to Acme (github.com/acme/[31mwork)',
    );
  });

  it('asks about the root it is given', () => {
    const asked: string[] = [];
    const gateway = {
      forwardingScope: (rootId: string): ForwardingScope => {
        asked.push(rootId);
        return { deploymentName: 'Acme', mode: 'machine' };
      },
    };
    forwardingLine(gateway, 'session-7');
    expect(asked).toEqual(['session-7']);
  });

  // A gateway that does not offer the capability forwards nothing as far as
  // the line can tell: the local gateway, or one an embedder installed.
  it('says nothing for a gateway that offers no forwarding scope', () => {
    expect(forwardingLine({ close: () => Promise.resolve() }, 's1')).toBeNull();
  });

  it('says nothing for a gateway that answers null', () => {
    expect(forwardingLine(answering(null), 's1')).toBeNull();
  });
});

// The line is read in the session start's `finally`, beside the store close. A
// throw out of it would cost the session every notice, so it answers null
// instead, the same answer a machine that forwards nothing gets.
describe('forwardingLine fails open', () => {
  it('answers null when the gateway throws', () => {
    const gateway = {
      forwardingScope: (): ForwardingScope => {
        throw new Error('scope unreadable');
      },
    };
    expect(forwardingLine(gateway, 's1')).toBeNull();
  });

  it('answers null when the scope it returns cannot be read', () => {
    // A scope whose name throws on access stands for any malformed answer.
    const scope = Object.defineProperty({ mode: 'machine' }, 'deploymentName', {
      get: () => {
        throw new Error('name unreadable');
      },
    }) as ForwardingScope;
    expect(forwardingLine(answering(scope), 's1')).toBeNull();
  });

  it('names the deployment when nothing throws', () => {
    // The control: the same shapes without the fault reach the line, so the
    // nulls above are the faults' doing.
    expect(forwardingLine(answering({ deploymentName: 'Acme', mode: 'machine' }), 's1')).toBe(
      'AKA: forwarding everything to Acme (machine-wide)',
    );
  });
});
