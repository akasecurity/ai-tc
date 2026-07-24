import { describe, expect, it } from 'vitest';

import {
  captureId,
  classifiedDataId,
  inspectionDefinitionId,
  inspectionFindingId,
  inventoryId,
  llmCallId,
  normalizeHost,
  promptId,
  shareCallSiteId,
  shareDestinationId,
  shareEndpointId,
  sourceProjectId,
} from '../src/ids.ts';

// These golden vectors freeze the exact hashes so an accidental change to a
// prefix, the JSON join, or the digest fails loudly instead of silently
// breaking local dedupe.
describe('meta-id content addressing (golden vectors)', () => {
  it('inventoryId is stable per object_type', () => {
    expect(inventoryId('host', 'my-laptop.local')).toBe(
      '0c365c4e74831079216a7a5dabc564b32c90197d61a64255ced5a7f7bdbceebe',
    );
    expect(inventoryId('harness', 'claude-code')).toBe(
      'baba69e251bc4df5b4c5a1bc79fae9d590515b4130206eda49ba89feac6ee348',
    );
    expect(inventoryId('user', 'person:abc123')).toBe(
      'becdd3df3dab826485635e29ceee07356f9337844aea44afc563b5d5d312fc2b',
    );
  });

  it('sourceProjectId is stable', () => {
    expect(sourceProjectId('https://github.com/akasecurity/ai-tc.git')).toBe(
      '9c7aa01ab82c82990b846f885919a1619e810b3dca090bb62852db0e1687f2da',
    );
  });

  it('classifiedDataId is stable', () => {
    expect(classifiedDataId('aws_secret_key')).toBe(
      'ee173b579d2c8f17522ffd54e34ffee136f6fdc20673a68d951673fc61f8108d',
    );
  });

  it('inspectionDefinitionId is stable', () => {
    expect(inspectionDefinitionId('aka.pii.email', '1.2.0')).toBe(
      '0ef109c4bc122c8e6e98faf907f9ad0dfe2b276bf2301e0d4c33f4c52948b047',
    );
  });

  it('object_type and identity_key both fold into the id', () => {
    expect(inventoryId('host', 'my-laptop.local')).not.toBe(
      inventoryId('harness', 'my-laptop.local'),
    );
    expect(inventoryId('host', 'my-laptop.local')).not.toBe(inventoryId('host', 'other.local'));
  });
});

// The finding id is keyed on the RULE id, not the inspection_definition id, so
// a re-detected hit keeps the same id across a rule version bump — only the
// definition reference (refreshed via the insert's ON CONFLICT DO UPDATE)
// tracks the new version. See the inspectionFindingId doc comment in ids.ts.
describe('inspectionFindingId (keyed on ruleId, not definitionId)', () => {
  it('is stable / deterministic for the same (event, rule, span)', () => {
    const id = inspectionFindingId('audit_evt_abc123', 'aka.secrets.aws-access-key', 14, 34);
    expect(id).toBe('cbd5462dd06a3b6f9507781966976e7e73db2218a550895e905f1a8977f2352d');
    expect(inspectionFindingId('audit_evt_abc123', 'aka.secrets.aws-access-key', 14, 34)).toBe(id);
  });

  it('a different span yields a different id', () => {
    expect(inspectionFindingId('audit_evt_abc123', 'aka.secrets.aws-access-key', 0, 10)).toBe(
      '601c07cac2fde2b3f31aeb24c232edc2b6df491ec5b96bdea1ad1ee03d51de38',
    );
  });

  it('a different rule id yields a different id', () => {
    expect(inspectionFindingId('audit_evt_abc123', 'aka.secrets.other-rule', 14, 34)).toBe(
      '94fafd16668051ecd84567af36457b175f338d1d6a58eb835f38a6474e870172',
    );
  });

  it('a different audit event yields a different id', () => {
    expect(inspectionFindingId('audit_evt_abc123', 'aka.secrets.aws-access-key', 14, 34)).not.toBe(
      inspectionFindingId('audit_evt_other', 'aka.secrets.aws-access-key', 14, 34),
    );
  });
});

// `llm_call` rows are transcript-derived and re-read on every reconcile pass, so
// the id MUST be deterministic — a random id would double-count tokens on
// re-scan. The id is keyed on (sessionId, message.id). `message.id` repeats
// within a transcript (one record per content block, plus streaming partials in
// subagent transcripts), so keying on it deliberately COLLAPSES those duplicates
// into one llm_call; within a single reconcile pass INSERT OR IGNORE makes the
// re-read a no-op. See the llmCallId doc comment in ids.ts for the full contract.
describe('llmCallId (deterministic transcript-row id)', () => {
  it('is stable / deterministic for the same (session, message)', () => {
    const id = llmCallId('sess_abc123', 'msg_01HZXYZ');
    expect(id).toBe('eb9f4c9e8317eb55ef360571342382ab381abe8504928c3b094c27164091ed7d');
    // Re-deriving the same tuple yields the byte-for-byte identical id.
    expect(llmCallId('sess_abc123', 'msg_01HZXYZ')).toBe(id);
  });

  it('distinct messages within a session get distinct ids', () => {
    expect(llmCallId('sess_abc123', 'msg_01HZXYZ')).not.toBe(llmCallId('sess_abc123', 'msg_other'));
  });

  it('distinct sessions get distinct ids for the same message id', () => {
    expect(llmCallId('sess_abc123', 'msg_01HZXYZ')).not.toBe(
      llmCallId('sess_other', 'msg_01HZXYZ'),
    );
  });
});

// `promptId` is the run-grouping key the tool_call/llm_call attribute bags
// reference as `run_key` — content-addressed on (session, transcript promptUuid)
// so every leaf spawned by the same user turn resolves to the same key.
describe('promptId (run-grouping key)', () => {
  it('is stable / deterministic for the same (session, promptUuid)', () => {
    const id = promptId('sess_abc123', 'e7f1a2b3-uuid-turn-1');
    expect(id).toBe('ac7c33f6b1ab5c75a093798e1df5a596daeda2517410d43194d30258f2acfeeb');
    expect(promptId('sess_abc123', 'e7f1a2b3-uuid-turn-1')).toBe(id);
  });

  it('distinct sessions get distinct ids for the same promptUuid', () => {
    expect(promptId('sess_other', 'e7f1a2b3-uuid-turn-1')).toBe(
      '8edeec77eb6f07eab4da4842d3d5d135706ce4cec26389d79f28516c80bdfeaa',
    );
  });

  it('distinct promptUuids within a session get distinct ids', () => {
    expect(promptId('sess_abc123', 'different-uuid')).toBe(
      '5e5cd041a99ef68efca87e856926c5b8b3367aabc1ffbeec2915bb7bff66e4e6',
    );
  });
});

// `captureId` content-addresses a capture on its own text hash, scoped to the
// owning session so identical content in two sessions never collapses onto one
// row. A `null` session (a capture taken outside any harness session) folds
// onto a fixed sentinel instead of shortening the join.
describe('captureId (content-addressed, session-scoped, path-scoped)', () => {
  it('is stable / deterministic for the same (session, contentHash, path)', () => {
    const id = captureId('sess_abc123', 'contenthash123');
    expect(id).toBe('812cee34ea16443f934a56575707669789d250a65563622d537c47af36b1fd35');
    expect(captureId('sess_abc123', 'contenthash123')).toBe(id);
  });

  it('a null session folds onto the fixed sentinel rather than being dropped', () => {
    expect(captureId(null, 'contenthash123')).toBe(
      '68787b92f533cd97454be0f5f56d043badd2481be6fc15ce3b0792a89a853078',
    );
  });

  it('a different content hash yields a different id', () => {
    expect(captureId('sess_abc123', 'contenthash456')).toBe(
      '7a7a1bc5f2bc39f58615aa418669072a923318b480e0e1fafcf7e02e54a15454',
    );
  });

  it('a different file path yields a different id — two identical-content files stay distinct', () => {
    expect(captureId('sess_abc123', 'contenthash123', 'src/a.ts')).toBe(
      '90eef03a6239d77df1c36f3b74b3f253ed6480cdd03909d82715adb0783f5674',
    );
    expect(captureId('sess_abc123', 'contenthash123', 'src/a.ts')).not.toBe(
      captureId('sess_abc123', 'contenthash123', 'src/b.ts'),
    );
    // A path-less capture folds onto the NO_PATH sentinel (the default).
    expect(captureId('sess_abc123', 'contenthash123', null)).toBe(
      captureId('sess_abc123', 'contenthash123'),
    );
  });
});

// The caller normalizes a host (via normalizeHost) before hashing AND before
// storing it, so repeat scans of the same destination collapse to one row.
describe('shareDestinationId (caller-normalized host)', () => {
  it('is stable for the golden vector', () => {
    expect(shareDestinationId('newrelic.com')).toBe(
      '454225bb8430c47e7439e93aa4c4cab5744010979d2a9661ea9b46869add735c',
    );
  });

  it('collapses case and trailing-dot variants once normalizeHost is applied', () => {
    expect(normalizeHost('Newrelic.com.')).toBe('newrelic.com');
    const base = shareDestinationId('newrelic.com');
    expect(shareDestinationId(normalizeHost('Newrelic.com.'))).toBe(base);
    expect(shareDestinationId(normalizeHost('NEWRELIC.COM'))).toBe(base);
  });
});

describe('shareEndpointId / shareCallSiteId', () => {
  it('shareEndpointId is stable for the golden vector', () => {
    expect(shareEndpointId('dest_abc', 'POST', 'https://api.newrelic.com/v1/ingest')).toBe(
      '30b95daa1dc695cd322dfd3a3a1f0603f9756fc5b5e4b9cc2ac5066f66176498',
    );
  });

  it('shareCallSiteId is stable for the golden vector', () => {
    expect(shareCallSiteId('endpoint_abc', 'payments-api', 'src/lib/telemetry.ts', 42)).toBe(
      '40015cd85d9d172866157ec2c1c5414d90c29fedaf2a33468c0ba63704cf506c',
    );
  });
});
