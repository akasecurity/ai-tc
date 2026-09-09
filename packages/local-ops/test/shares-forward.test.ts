import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  removeControlPlaneCredential,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type {
  EgressIngestRequest,
  RecordProjectEgressInput,
  RemoteFailureKind,
  ResolvedEgressHit,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import type { SharesForwardConnection, SharesForwardSendResult } from '../src/shares-forward.ts';
import { forwardProjectEgress } from '../src/shares-forward.ts';

const ENDPOINT = 'https://aka.acme.test';
const OTHER_ENDPOINT = 'https://aka.other.test';
const TEST_KEY = 'not-a-real-key';
const SNIPPET = 'const client = new Stripe(readTheKeyFromSomewhere());';

// Every send this suite performs, so a case can assert both what the sender was
// handed and that it was never reached at all.
interface Sent {
  connection: SharesForwardConnection;
  request: EgressIngestRequest;
}

function recorder(answer: SharesForwardSendResult | (() => never)) {
  const sent: Sent[] = [];
  return {
    sent,
    send: (connection: SharesForwardConnection, request: EgressIngestRequest) => {
      sent.push({ connection, request });
      if (typeof answer === 'function') return answer();
      return Promise.resolve(answer);
    },
  };
}

const hit = (file: string): ResolvedEgressHit => ({
  host: 'api.stripe.com',
  kind: 'provider',
  name: 'Stripe',
  category: 'payments',
  trust: 'recognized',
  network: null,
  method: 'POST',
  transport: 'https',
  url: 'https://api.stripe.com/v1/charges',
  template: false,
  dataClass: 'customer',
  site: { file, line: 42, snippet: SNIPPET, dynamic: false, vendored: false },
});

const input = (over: Partial<RecordProjectEgressInput> = {}): RecordProjectEgressInput => ({
  projectKey: 'git:https://github.com/acme/payments-api.git',
  project: 'payments-api',
  projectId: 'source-project-1',
  reconcile: { mode: 'walk', walkedPrefix: 'src' },
  hits: [hit('src/billing/charge.ts'), hit('src/billing/refund.ts')],
  ...over,
});

let home: string;

// An attachment is both halves: the settings descriptor that names a deployment
// and a credential file minted for that same deployment. Written through the
// real writers, so what this reads back is what an attach actually produces.
function attach(options: { label?: string; credentialFor?: string | null } = {}): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: {
        endpoint: ENDPOINT,
        attachedAt: '2026-09-01T10:00:00.000Z',
        ...(options.label === undefined ? {} : { label: options.label }),
      },
    },
    home,
    // No managed overlay: an administrator's file on the machine running this
    // suite must not decide what these cases see.
    null,
  );
  const credentialFor = options.credentialFor === undefined ? ENDPOINT : options.credentialFor;
  if (credentialFor === null) {
    removeControlPlaneCredential(settingsDir(home));
    return;
  }
  writeControlPlaneCredential(settingsDir(home), {
    specVersion: 1,
    endpoint: credentialFor,
    apiKey: TEST_KEY,
  });
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-shares-forward-'));
});

afterEach(() => {
  removeTrees([home]);
});

describe('forwardProjectEgress — machines with nothing to forward to', () => {
  it('reports not-attached for a home with no attachment, and sends nothing', async () => {
    const transport = recorder({ ok: true });

    const outcome = await forwardProjectEgress(home, input(), { send: transport.send });

    expect(outcome).toEqual({ status: 'not-attached' });
    expect(transport.sent).toHaveLength(0);
  });

  it('reports not-attached for a mode with no descriptor to name', async () => {
    // Half an attachment names no deployment, so there is nothing to forward to
    // and nothing to print — the same silence a standalone machine gets.
    applyOnboarding({ runMode: 'attached' }, home, null);
    const transport = recorder({ ok: true });

    const outcome = await forwardProjectEgress(home, input(), { send: transport.send });

    expect(outcome).toEqual({ status: 'not-attached' });
    expect(transport.sent).toHaveLength(0);
  });
});

describe('forwardProjectEgress — attached, but not sending', () => {
  it('reports disabled when the caller opted this run out', async () => {
    attach();
    const transport = recorder({ ok: true });

    const outcome = await forwardProjectEgress(home, input(), {
      send: transport.send,
      enabled: false,
    });

    expect(outcome).toEqual({ status: 'disabled', endpoint: ENDPOINT });
    expect(transport.sent).toHaveLength(0);
  });

  it('reports disabled ahead of the credential read, so an opt-out is never misread', async () => {
    // The opt-out means "no network this run", so it has to be answered before
    // the credential is looked at. Read in the other order, a machine that
    // asked for no network and has no usable credential would be told to
    // re-attach — advice for a problem it did not have.
    attach({ credentialFor: null });
    const transport = recorder({ ok: true });

    const outcome = await forwardProjectEgress(home, input(), {
      send: transport.send,
      enabled: false,
    });

    expect(outcome).toEqual({ status: 'disabled', endpoint: ENDPOINT });
    expect(transport.sent).toHaveLength(0);
  });

  it('reports no-credential when the credential file is absent', async () => {
    attach({ credentialFor: null });
    const transport = recorder({ ok: true });

    const outcome = await forwardProjectEgress(home, input(), { send: transport.send });

    expect(outcome).toEqual({ status: 'no-credential', endpoint: ENDPOINT });
    expect(transport.sent).toHaveLength(0);
  });

  it('reports no-credential when the stored credential names another deployment', async () => {
    // A credential minted for one deployment is not a credential for this one,
    // and presenting it would hand a bearer token to an endpoint that never
    // issued it.
    attach({ credentialFor: OTHER_ENDPOINT });
    const transport = recorder({ ok: true });

    const outcome = await forwardProjectEgress(home, input(), { send: transport.send });

    expect(outcome).toEqual({ status: 'no-credential', endpoint: ENDPOINT });
    expect(transport.sent).toHaveLength(0);
  });
});

describe('forwardProjectEgress — the send', () => {
  it('forwards and counts the call sites the body actually carries', async () => {
    attach();
    const transport = recorder({ ok: true });

    const outcome = await forwardProjectEgress(home, input(), { send: transport.send });

    expect(outcome).toEqual({ status: 'forwarded', endpoint: ENDPOINT, callSites: 2 });
    expect(transport.sent).toHaveLength(1);
  });

  it('presents the endpoint and the credential the attachment names', async () => {
    attach();
    const transport = recorder({ ok: true });

    await forwardProjectEgress(home, input(), { send: transport.send });

    expect(transport.sent[0]?.connection).toEqual({ endpoint: ENDPOINT, apiKey: TEST_KEY });
  });

  it('sends the projection, never the resolved input', async () => {
    attach();
    const transport = recorder({ ok: true });

    await forwardProjectEgress(home, input(), { send: transport.send });

    const body = JSON.stringify(transport.sent[0]?.request);
    // The things the projection exists to remove, asserted over the serialized
    // body rather than the object graph — the body is what a deployment gets.
    expect(body).not.toContain('"snippet"');
    expect(body).not.toContain(SNIPPET);
    expect(body).not.toContain('"projectId"');
    expect(body).not.toContain('git:');
    expect(transport.sent[0]?.request.projectKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('carries the display name and the reconcile the input resolved', async () => {
    attach();
    const transport = recorder({ ok: true });

    await forwardProjectEgress(home, input(), { send: transport.send });

    // The reconcile decides what the deployment REPLACES, so it has to be the
    // one the local write used — a subtree scan that forwarded a root-scoped
    // reconcile would clear the rest of the project on the server.
    expect(transport.sent[0]?.request.reconcile).toEqual({ mode: 'walk', walkedPrefix: 'src' });
    expect(transport.sent[0]?.request.project).toBe('payments-api');
  });

  it('names the deployment by its label when the attachment carries one', async () => {
    attach({ label: 'Acme Security' });
    const transport = recorder({ ok: true });

    const outcome = await forwardProjectEgress(home, input(), { send: transport.send });

    // The label is what a person recognises; the raw URL is only the fallback.
    expect(outcome).toEqual({ status: 'forwarded', endpoint: 'Acme Security', callSites: 2 });
    // The transport still gets the real endpoint — a label is display only.
    expect(transport.sent[0]?.connection.endpoint).toBe(ENDPOINT);
  });

  it('forwards an empty register rather than skipping it', async () => {
    // A project whose destinations were all removed still has to say so, or the
    // deployment keeps showing call sites the tree no longer contains.
    attach();
    const transport = recorder({ ok: true });

    const outcome = await forwardProjectEgress(home, input({ hits: [] }), {
      send: transport.send,
    });

    expect(outcome).toEqual({ status: 'forwarded', endpoint: ENDPOINT, callSites: 0 });
    expect(transport.sent).toHaveLength(1);
  });
});

describe('forwardProjectEgress — a send that did not land', () => {
  const kinds: RemoteFailureKind[] = [
    'unauthorized',
    'forbidden',
    'route-absent',
    'invalid-request',
    'rejected',
    'unreachable',
  ];

  for (const kind of kinds) {
    it(`reports the sender's ${kind} verdict unchanged`, async () => {
      attach();
      const transport = recorder({ ok: false, kind });

      const outcome = await forwardProjectEgress(home, input(), { send: transport.send });

      expect(outcome).toEqual({ status: 'failed', endpoint: ENDPOINT, kind });
    });
  }

  it('turns a sender that throws into unreachable rather than a throw of its own', async () => {
    // The local write already happened; nothing here may cost the caller its
    // result. A transport that came apart is the same "try again" as a timeout.
    attach();
    const transport = recorder(() => {
      throw new Error('socket hang up');
    });

    const outcome = await forwardProjectEgress(home, input(), { send: transport.send });

    expect(outcome).toEqual({ status: 'failed', endpoint: ENDPOINT, kind: 'unreachable' });
    expect(transport.sent).toHaveLength(1);
  });

  it('reports not-attached when it fails before a deployment is named', async () => {
    // Nothing was going to be sent, so there is no endpoint to put in a line,
    // and inventing one would name a deployment this machine never resolved.
    const missing = join(home, 'no', 'such', 'home');
    const transport = recorder({ ok: true });

    const outcome = await forwardProjectEgress(missing, input(), { send: transport.send });

    expect(outcome).toEqual({ status: 'not-attached' });
    expect(transport.sent).toHaveLength(0);
  });
});
