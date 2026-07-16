import { describe, expect, it } from 'vitest';

import {
  classifiedDataId,
  inspectionDefinitionId,
  inventoryId,
  llmCallId,
  normalizeHost,
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
