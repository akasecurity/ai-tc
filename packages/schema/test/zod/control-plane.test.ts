import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import type { StorePostureSnapshot as StorePostureSnapshotT } from '../../src/zod/control-plane.ts';
import {
  ATTACHED_CREDENTIAL_FILENAME,
  ATTACHED_CREDENTIAL_SPEC_VERSION,
  AttachedCredential,
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
