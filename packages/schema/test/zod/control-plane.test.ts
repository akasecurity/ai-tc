import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import type { StorePostureSnapshot as StorePostureSnapshotT } from '../../src/zod/control-plane.ts';
import {
  AttachDeviceGrant,
  AttachDeviceRequest,
  ATTACHED_CREDENTIAL_FILENAME,
  ATTACHED_CREDENTIAL_SPEC_VERSION,
  AttachedCredential,
  AttachTokenIssued,
  AttachTokenResponse,
  ControlPlaneErrorBody,
  IngestAck,
  PluginWhoami,
  RecordAuditEventRequest,
  StorePosturePack,
  StorePosturePlugin,
  StorePostureSnapshot,
} from '../../src/zod/control-plane.ts';

// ─── Fixtures ────────────────────────────────────────────────────────────────

const MAX_DATE_MS = 253_402_300_799_999;
const MAX_INT4 = 2_147_483_647;

const credential = {
  specVersion: ATTACHED_CREDENTIAL_SPEC_VERSION,
  endpoint: 'https://aka.example-org.internal',
  apiKey: 'aka_live_0123456789abcdef',
  keyPrefix: 'aka_live',
  mintedAt: '2026-08-24T10:00:00.000Z',
};

const policyCounts = {
  total: 7,
  disabled: 1,
  byAction: { warn: 3, redact: 2, block: 1, allow: 0, log: 1 },
};

const snapshot: StorePostureSnapshotT = {
  deviceId: '6f2d64f0-b6a4-4bb1-9a3c-6a4c26f5c9d1',
  hostname: 'dev-laptop.local',
  capturedAt: 1_766_000_000_000,
  storePresent: true,
  schemaVersion: 12,
  findingsTotal: 42,
  findingsFirstAt: 1_760_000_000_000,
  findingsLastAt: 1_765_999_999_999,
  packs: [{ packId: 'aka/secrets', version: '1.4.0', enabled: true, updatedAt: null }],
  policyCounts,
};

const auditEvent = {
  id: 'evt-1',
  eventType: 'session',
  startedAt: '2026-08-24T10:00:00.000Z',
} as const;

// ─── AttachedCredential ──────────────────────────────────────────────────────

describe('AttachedCredential', () => {
  it('parses a full credential record', () => {
    expect(AttachedCredential.parse(credential)).toEqual(credential);
  });

  it('requires the endpoint the credential was minted against', () => {
    // The endpoint binding is what lets the transport refuse to present the
    // key to a host settings.json was later edited to name.
    expect(AttachedCredential.safeParse({ ...credential, endpoint: undefined }).success).toBe(
      false,
    );
    expect(AttachedCredential.safeParse({ ...credential, endpoint: '' }).success).toBe(false);
  });

  it('requires a non-empty key and the exact spec version', () => {
    expect(AttachedCredential.safeParse({ ...credential, apiKey: '' }).success).toBe(false);
    expect(AttachedCredential.safeParse({ ...credential, specVersion: 2 }).success).toBe(false);
  });

  it('carries NO meta id — the credential shape must never reach a schema registry', () => {
    // Same protection WorkspaceSettings relies on: a consumer walking
    // z.globalRegistry publishes every entry it finds.
    expect(z.globalRegistry.get(AttachedCredential)).toBeUndefined();
  });

  it('pins the on-disk filename', () => {
    expect(ATTACHED_CREDENTIAL_FILENAME).toBe('control-plane-credential.json');
  });
});

// ─── StorePostureSnapshot ────────────────────────────────────────────────────

describe('StorePostureSnapshot', () => {
  it('parses a snapshot without the optional plugin block', () => {
    expect(StorePostureSnapshot.parse(snapshot)).toEqual(snapshot);
  });

  it('parses a snapshot with the plugin block, blanks included', () => {
    // Blank-but-bounded strings are deliberately accepted (fail-open channel);
    // a receiver collapses them at its own write boundary.
    const plugin = {
      package: '@akasecurity/ai-tc-claude-code',
      version: '0.9.7',
      ossVersion: '',
      policyBundleVersion: null,
      policyFetchedAt: null,
    };
    expect(StorePostureSnapshot.parse({ ...snapshot, plugin }).plugin).toEqual(plugin);
  });

  it('bounds capturedAt at the largest round-trippable timestamp', () => {
    expect(StorePostureSnapshot.safeParse({ ...snapshot, capturedAt: MAX_DATE_MS }).success).toBe(
      true,
    );
    expect(
      StorePostureSnapshot.safeParse({ ...snapshot, capturedAt: MAX_DATE_MS + 1 }).success,
    ).toBe(false);
  });

  /**
   * The findings window carries epoch millis too, and until recently carried
   * only `.min(0)`.
   *
   * Worth its own case rather than folding into the `capturedAt` one above,
   * because these two are read from the local store's ROWS rather than from
   * this machine's clock — so a damaged or hand-edited store is enough to
   * produce an out-of-range value with no clock skew involved.
   */
  it.each(['findingsFirstAt', 'findingsLastAt'] as const)(
    'bounds %s at the largest round-trippable timestamp',
    (field) => {
      // Positive control first: the bound admits the largest legal value, so a
      // schema that rejected everything would not pass this by accident.
      expect(StorePostureSnapshot.safeParse({ ...snapshot, [field]: MAX_DATE_MS }).success).toBe(
        true,
      );
      expect(
        StorePostureSnapshot.safeParse({ ...snapshot, [field]: MAX_DATE_MS + 1 }).success,
      ).toBe(false);
      // And null stays legal — the field is nullable, and a bound that broke
      // that would be a different regression this case would otherwise hide.
      expect(StorePostureSnapshot.safeParse({ ...snapshot, [field]: null }).success).toBe(true);
    },
  );

  it('bounds the int4 members', () => {
    expect(
      StorePostureSnapshot.safeParse({ ...snapshot, findingsTotal: MAX_INT4 + 1 }).success,
    ).toBe(false);
    expect(
      StorePostureSnapshot.safeParse({ ...snapshot, schemaVersion: MAX_INT4 + 1 }).success,
    ).toBe(false);
  });

  it('requires every action key in policyCounts.byAction and refuses an unknown one', () => {
    expect(
      StorePostureSnapshot.safeParse({
        ...snapshot,
        policyCounts: { ...policyCounts, byAction: { ...policyCounts.byAction, log: undefined } },
      }).success,
    ).toBe(false);
    expect(
      StorePostureSnapshot.safeParse({
        ...snapshot,
        policyCounts: { ...policyCounts, byAction: { ...policyCounts.byAction, bogus: 1 } },
      }).success,
    ).toBe(false);
  });

  it('caps packs at 500', () => {
    const pack = { packId: 'aka/x', version: '1', enabled: true, updatedAt: null };
    expect(
      StorePostureSnapshot.safeParse({ ...snapshot, packs: Array(501).fill(pack) }).success,
    ).toBe(false);
  });

  it('registers the request shapes under their component ids', () => {
    // Request bodies are the single source of truth shared with the control
    // plane; the id is how a generated document names them. Pinned so a rename
    // is a deliberate contract change, never a refactor side effect.
    expect(z.globalRegistry.get(StorePostureSnapshot)?.id).toBe('StorePostureSnapshot');
    expect(z.globalRegistry.get(StorePosturePack)?.id).toBe('StorePosturePack');
    expect(z.globalRegistry.get(StorePosturePlugin)?.id).toBe('StorePosturePlugin');
    expect(z.globalRegistry.get(RecordAuditEventRequest)?.id).toBe('RecordAuditEventRequest');
  });
});

// ─── RecordAuditEventRequest ─────────────────────────────────────────────────

describe('RecordAuditEventRequest', () => {
  it('accepts a plain AuditEventInput body and defaults inspections to []', () => {
    expect(RecordAuditEventRequest.parse(auditEvent).inspections).toEqual([]);
  });

  it('refuses an inspection claiming the capture/ version namespace', () => {
    const inspection = {
      ruleId: 'secrets/aws-access-key',
      ruleName: 'AWS access key',
      ruleVersion: 'capture/secret/high',
      category: 'secret',
      severity: 'high',
      span: { start: 0, end: 4 },
      maskedMatch: 'AKIA…',
      actionTaken: 'redact',
      confidence: 1,
    };
    const result = RecordAuditEventRequest.safeParse({
      ...auditEvent,
      eventType: 'tool_call',
      inspections: [inspection],
    });
    expect(result.success).toBe(false);
    expect(
      RecordAuditEventRequest.safeParse({
        ...auditEvent,
        eventType: 'tool_call',
        inspections: [{ ...inspection, ruleVersion: '3' }],
      }).success,
    ).toBe(true);
  });
});

// ─── Lenient response parsers ────────────────────────────────────────────────

describe('response parsers', () => {
  it('IngestAck strips unknown keys instead of failing on a newer control plane', () => {
    expect(IngestAck.parse({ accepted: 2, duplicates: 1, newerField: 'x' })).toEqual({
      accepted: 2,
      duplicates: 1,
    });
  });

  it('PluginWhoami tolerates values a control plane types more narrowly', () => {
    const whoami = {
      tenantName: 'Example Org',
      userEmail: 'dev@example.com',
      role: 'a-role-this-client-has-never-heard-of',
      keyKind: 'plugin',
      serverTime: '2026-08-24T10:00:00.000Z',
      extra: true,
    };
    expect(PluginWhoami.parse(whoami).role).toBe('a-role-this-client-has-never-heard-of');
  });

  it('PluginWhoami refuses control characters, which reach a terminal verbatim', () => {
    // `aka attach` prints every one of these into the user's terminal. A plane
    // is authenticated, not trusted: an escape sequence could repaint the line
    // or hide what just happened, and a bare newline forges an extra field in
    // the block. Refusing at the shape means no render site has to remember.
    const ok = {
      tenantName: 'Example Org',
      userEmail: 'dev@example.com',
      role: 'member',
      keyKind: 'plugin',
      serverTime: '2026-08-24T10:00:00.000Z',
    };
    expect(PluginWhoami.safeParse(ok).success).toBe(true);
    expect(PluginWhoami.safeParse({ ...ok, tenantName: 'Evil\u001b[2KOrg' }).success).toBe(false);
    expect(PluginWhoami.safeParse({ ...ok, tenantName: 'line one\nline two' }).success).toBe(false);
    // …and it is bounded, so a plane cannot flood the terminal either.
    expect(PluginWhoami.safeParse({ ...ok, tenantName: 'x'.repeat(201) }).success).toBe(false);
  });

  it('ControlPlaneErrorBody accepts an empty object — the status code is the contract', () => {
    expect(ControlPlaneErrorBody.parse({})).toEqual({});
    expect(ControlPlaneErrorBody.parse({ error: { code: 'forbidden' } }).error?.code).toBe(
      'forbidden',
    );
  });

  it('registers none of the response parsers', () => {
    expect(z.globalRegistry.get(IngestAck)).toBeUndefined();
    expect(z.globalRegistry.get(PluginWhoami)).toBeUndefined();
    expect(z.globalRegistry.get(ControlPlaneErrorBody)).toBeUndefined();
  });
});

// ─── The device-authorization attach flow ────────────────────────────────────

describe('AttachDeviceRequest', () => {
  const request = {
    deviceId: 'd76504a1-fab2-4e28-af82-b5aab7212fdc',
    hostname: 'dev-laptop',
    os: 'darwin 24.0.0',
    cliVersion: '0.9.8',
  };

  it('accepts what the CLI reports about itself', () => {
    expect(AttachDeviceRequest.safeParse(request).success).toBe(true);
    expect(AttachDeviceRequest.safeParse({ ...request, label: 'Work laptop' }).success).toBe(true);
  });

  // Required, so an approval page always has something to render. A caller that
  // cannot determine its hostname substitutes a placeholder — a visible
  // decision — rather than leaving the server to render a blank.
  it.each(['deviceId', 'hostname', 'os', 'cliVersion'])('refuses an empty %s', (field) => {
    expect(AttachDeviceRequest.safeParse({ ...request, [field]: '' }).success).toBe(false);
  });

  // Unauthenticated, so every one of these is attacker-chosen. Length caps are
  // what stop a grant row being an arbitrary-size write.
  it('caps every device-supplied string', () => {
    expect(AttachDeviceRequest.safeParse({ ...request, hostname: 'h'.repeat(256) }).success).toBe(
      false,
    );
    expect(AttachDeviceRequest.safeParse({ ...request, os: 'o'.repeat(65) }).success).toBe(false);
    expect(AttachDeviceRequest.safeParse({ ...request, cliVersion: 'v'.repeat(65) }).success).toBe(
      false,
    );
    expect(AttachDeviceRequest.safeParse({ ...request, label: 'l'.repeat(201) }).success).toBe(
      false,
    );
    expect(AttachDeviceRequest.safeParse({ ...request, deviceId: 'd'.repeat(129) }).success).toBe(
      false,
    );
  });

  // These strings are rendered on an approval page and echoed by the CLI. An
  // escape sequence in a hostname would repaint the very block a user is
  // reading to decide whether to approve.
  it('refuses control characters in what the device claims', () => {
    expect(AttachDeviceRequest.safeParse({ ...request, hostname: 'a\u001b[2Kb' }).success).toBe(
      false,
    );
    expect(AttachDeviceRequest.safeParse({ ...request, label: 'two\nlines' }).success).toBe(false);
  });
});

describe('AttachTokenResponse', () => {
  it('reads each state the flow defines', () => {
    for (const body of [
      { status: 'pending' },
      { status: 'slow_down', interval: 10 },
      { status: 'denied' },
      { status: 'denied', message: 'your role cannot attach machines' },
      { status: 'expired' },
      { status: 'issued', apiKey: 'aka_live_x', endpoint: 'https://aka.example.test' },
    ]) {
      expect(AttachTokenResponse.safeParse(body), JSON.stringify(body)).toMatchObject({
        success: true,
      });
    }
  });

  // The leniency that lets the CLI ship ahead of a deployment, and outlive one.
  // A sixth state must not turn a poll into a parse error — the client's rule is
  // to keep waiting for a status it does not recognise, which it can only do if
  // the parse succeeded.
  it('accepts a status it has never heard of rather than failing', () => {
    expect(AttachTokenResponse.safeParse({ status: 'authorization_pending' }).success).toBe(true);
  });

  // Order is load-bearing: the catch-all is last, so a WELL-FORMED known state
  // must still parse as itself and keep its own fields.
  it('prefers a known state over the catch-all', () => {
    expect(AttachTokenResponse.parse({ status: 'slow_down', interval: 10 })).toEqual({
      status: 'slow_down',
      interval: 10,
    });
  });

  // The safe degradation. An `issued` with no key fails the issued member and
  // lands on the catch-all as an unrecognised status, so a client waits instead
  // of attaching with nothing — never a shape that says "issued" and carries no
  // credential.
  it('does not read a keyless issued body as an issued credential', () => {
    const parsed = AttachTokenResponse.parse({ status: 'issued' });
    expect(parsed).not.toHaveProperty('apiKey');
    expect(Object.keys(parsed)).toEqual(['status']);
  });

  it('rejects a body with no status at all', () => {
    expect(AttachTokenResponse.safeParse({}).success).toBe(false);
  });

  // Same rule, and the same reason, as AttachedCredential: this member carries a
  // bearer credential, and a meta id would register it in the global registry
  // for anything walking that registry to publish.
  it('carries NO meta id on the member that holds the credential', () => {
    expect(z.globalRegistry.get(AttachTokenIssued)).toBeUndefined();
    expect(z.globalRegistry.get(AttachTokenResponse)).toBeUndefined();
    expect(z.globalRegistry.get(AttachDeviceGrant)).toBeUndefined();
  });
});

describe('AttachDeviceGrant', () => {
  const grant = {
    deviceCode: 'd'.repeat(64),
    userCode: 'ABCD-EFGH',
    verificationUri: 'https://aka.example.test/attach',
    expiresIn: 600,
    interval: 5,
  };

  it('reads a grant, with or without the prefilled link', () => {
    expect(AttachDeviceGrant.safeParse(grant).success).toBe(true);
    expect(
      AttachDeviceGrant.safeParse({
        ...grant,
        verificationUriComplete: 'https://aka.example.test/attach?code=ABCD-EFGH',
      }).success,
    ).toBe(true);
  });

  // Everything here is printed into a terminal by a client that has not yet
  // established which deployment it is talking to.
  it('refuses control characters in anything it will print', () => {
    expect(AttachDeviceGrant.safeParse({ ...grant, userCode: 'AB\u001b[1;1H' }).success).toBe(
      false,
    );
    expect(
      AttachDeviceGrant.safeParse({ ...grant, verificationUri: 'https://x.test\nfake: line' })
        .success,
    ).toBe(false);
  });

  it('requires a positive expiry and interval', () => {
    expect(AttachDeviceGrant.safeParse({ ...grant, expiresIn: 0 }).success).toBe(false);
    expect(AttachDeviceGrant.safeParse({ ...grant, interval: -1 }).success).toBe(false);
  });
});
