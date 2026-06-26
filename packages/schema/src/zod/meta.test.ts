import { describe, expect, it } from 'vitest';

import {
  toAuditEventRow,
  toClassifiedDataRow,
  toInspectionDefinitionRow,
  toInspectionFindingRow,
  toInventoryRow,
  toSourceProjectRow,
} from './local.ts';
import {
  AuditEventType,
  canonicalIdentity,
  HostAttributes,
  InventoryInput,
  InventoryObjectType,
  LlmCallAttributes,
  SessionTokenReport,
  TokenRollup,
} from './meta.ts';

const ISO = '2026-06-23T00:00:00.000Z';

describe('canonicalIdentity', () => {
  it('is injective: distinct part lists never collide', () => {
    expect(canonicalIdentity(['a', 'b'])).not.toBe(canonicalIdentity(['ab', '']));
    expect(canonicalIdentity(['a', 'b'])).toBe(canonicalIdentity(['a', 'b']));
  });

  it('encodes embedded quotes/separators safely', () => {
    expect(canonicalIdentity(['a"b', 'c'])).not.toBe(canonicalIdentity(['a', 'b"c']));
  });
});

describe('canonical attribute vocabulary', () => {
  it('validates canonical keys and passes the long tail through', () => {
    const parsed = HostAttributes.parse({
      host_name: 'laptop',
      os: 'darwin',
      os_version: '25.5.0',
      arch: 'arm64',
      // long tail — not in the vocab, kept as-is.
      kernel: '24.0.0',
    });
    expect(parsed.os_version).toBe('25.5.0');
    expect(parsed.kernel).toBe('24.0.0');
  });

  it('discriminators reject unknown members', () => {
    expect(InventoryObjectType.safeParse('host').success).toBe(true);
    expect(InventoryObjectType.safeParse('robot').success).toBe(false);
    // event_type is a superset of today's capture grain (deliberate widening).
    for (const t of ['session', 'tool_call', 'prompt', 'response', 'code_change']) {
      expect(AuditEventType.safeParse(t).success).toBe(true);
    }
  });

  it('InventoryInput requires a non-empty identity key', () => {
    expect(InventoryInput.safeParse({ objectType: 'host', identityKey: '' }).success).toBe(false);
    const ok = InventoryInput.parse({ objectType: 'host', identityKey: 'machine-1' });
    expect(ok.attributes).toEqual({}); // defaulted bag
  });
});

describe('LlmCallAttributes', () => {
  it('accepts a real usage bag and passes the long tail through', () => {
    // The verified sample `usage` object from a real transcript,
    // flattened the way the reconciler builds the bag (cache_creation.* and
    // server_tool_use.* promoted to top-level keys) plus model/provider and the
    // correlation ids stamped on every llm_call row.
    const parsed = LlmCallAttributes.parse({
      model: 'claude-opus-4-8',
      provider: 'anthropic',
      input_tokens: 8424,
      cache_creation_input_tokens: 7420,
      cache_read_input_tokens: 11404,
      output_tokens: 1202,
      web_search_requests: 0,
      web_fetch_requests: 0,
      service_tier: 'standard',
      ephemeral_1h_input_tokens: 7420,
      ephemeral_5m_input_tokens: 0,
      stop_reason: 'end_turn',
      message_id: 'msg_01abc',
      uuid: 'a1b2c3',
      parent_uuid: 'd4e5f6',
      run_key: 'prompt_xyz',
      // long tail — not in the vocab, kept as-is (e.g. raw nested usage fields).
      inference_geo: 'not_available',
      speed: 'standard',
    });
    expect(parsed.input_tokens).toBe(8424);
    expect(parsed.cache_creation_input_tokens).toBe(7420);
    expect(parsed.provider).toBe('anthropic');
    expect(parsed.run_key).toBe('prompt_xyz');
    expect(parsed.inference_geo).toBe('not_available');
  });

  it('tolerates missing optional fields (non-Anthropic / sparse providers)', () => {
    // A gateway/local provider may report only headline counts; every field is
    // optional so the parse still succeeds.
    const parsed = LlmCallAttributes.parse({
      model: 'llama3:70b',
      input_tokens: 100,
      output_tokens: 50,
    });
    expect(parsed.input_tokens).toBe(100);
    expect(parsed.cache_read_input_tokens).toBeUndefined();
    // An entirely empty bag is still valid.
    expect(LlmCallAttributes.safeParse({}).success).toBe(true);
  });

  it('rejects negative or non-integer token counts', () => {
    expect(LlmCallAttributes.safeParse({ input_tokens: -1 }).success).toBe(false);
    expect(LlmCallAttributes.safeParse({ output_tokens: 1.5 }).success).toBe(false);
  });
});

describe('token-usage read DTOs', () => {
  it('TokenRollup registers as an OpenAPI component now that getActivitySession references it', () => {
    expect(TokenRollup.meta()?.id).toBe('TokenRollup');
  });

  it('TokenRollup parses a representative rollup with a derived cost', () => {
    const rollup = TokenRollup.parse({
      sessionId: 'sess-1',
      model: 'claude-opus-4-8',
      provider: 'anthropic',
      inputTokens: 8424,
      outputTokens: 1202,
      cacheCreation: 7420,
      cacheRead: 11404,
      totalTokens: 28450,
      estimatedCostUsd: 0.1234,
    });
    expect(rollup.totalTokens).toBe(28450);
    expect(rollup.estimatedCostUsd).toBe(0.1234);
  });

  it('TokenRollup allows a null cost (unknown provider/model pair)', () => {
    const rollup = TokenRollup.parse({
      sessionId: 'sess-1',
      model: 'mystery-model',
      provider: 'gateway',
      inputTokens: 1,
      outputTokens: 1,
      cacheCreation: 0,
      cacheRead: 0,
      totalTokens: 2,
      estimatedCostUsd: null,
    });
    expect(rollup.estimatedCostUsd).toBeNull();
  });

  it('SessionTokenReport parses a representative session report (all priced)', () => {
    const report = SessionTokenReport.parse({
      sessionId: 'sess-1',
      rollups: [
        {
          sessionId: 'sess-1',
          model: 'claude-opus-4-8',
          provider: 'anthropic',
          inputTokens: 8424,
          outputTokens: 1202,
          cacheCreation: 7420,
          cacheRead: 11404,
          totalTokens: 28450,
          estimatedCostUsd: 0.1234,
        },
      ],
      totalTokens: 28450,
      estimatedCostUsd: 0.1234,
      costIsPartial: false,
    });
    expect(report.rollups).toHaveLength(1);
    expect(report.totalTokens).toBe(28450);
    expect(report.costIsPartial).toBe(false);
  });

  it('SessionTokenReport flags costIsPartial with a mix of priced/unpriced rollups', () => {
    const report = SessionTokenReport.parse({
      sessionId: 'sess-1',
      rollups: [
        {
          sessionId: 'sess-1',
          model: 'claude-opus-4-8',
          provider: 'anthropic',
          inputTokens: 8424,
          outputTokens: 1202,
          cacheCreation: 7420,
          cacheRead: 11404,
          totalTokens: 28450,
          estimatedCostUsd: 0.1234,
        },
        {
          sessionId: 'sess-1',
          model: 'mystery-model',
          provider: 'gateway',
          inputTokens: 100,
          outputTokens: 50,
          cacheCreation: 0,
          cacheRead: 0,
          totalTokens: 150,
          estimatedCostUsd: null,
        },
      ],
      totalTokens: 28600,
      // Σ of the priced rollup only; the unpriced one is excluded from the total.
      estimatedCostUsd: 0.1234,
      costIsPartial: true,
    });
    expect(report.rollups).toHaveLength(2);
    expect(report.costIsPartial).toBe(true);
  });

  it('SessionTokenReport requires costIsPartial', () => {
    expect(
      SessionTokenReport.safeParse({
        sessionId: 'sess-1',
        rollups: [],
        totalTokens: 0,
        estimatedCostUsd: null,
      }).success,
    ).toBe(false);
  });
});

describe('meta row mappers', () => {
  it('toInventoryRow stamps the id, JSON-encodes the bag, sets lifecycle stamps', () => {
    const row = toInventoryRow(
      {
        objectType: 'host',
        identityKey: 'machine-1',
        title: 'laptop',
        location: 'office',
        attributes: { os_version: '25.5.0' },
      },
      'inv-id',
      1000,
    );
    expect(row).toMatchObject({
      id: 'inv-id',
      objectType: 'host',
      title: 'laptop',
      location: 'office',
      hostId: null,
      firstSeen: 1000,
      lastSeen: 1000,
    });
    expect(row.attributes).toBe(JSON.stringify({ os_version: '25.5.0' }));
  });

  it('toSourceProjectRow carries the url and bag', () => {
    const row = toSourceProjectRow(
      { url: 'https://github.com/org/repo.git', name: 'repo', attributes: {} },
      'sp-id',
      2000,
    );
    expect(row).toMatchObject({
      id: 'sp-id',
      url: 'https://github.com/org/repo.git',
      name: 'repo',
    });
    expect(row.firstSeen).toBe(2000);
  });

  it('toAuditEventRow stamps identity, converts ISO->epoch, JSON-encodes attrs', () => {
    const row = toAuditEventRow({
      id: 'evt-1',
      eventType: 'session',
      startedAt: ISO,
      hostId: 'host-1',
      harnessId: 'harness-1',
      sourceProjectId: 'sp-1',
      attributes: { os_version: '25.5.0' },
    });
    expect(row).toMatchObject({
      id: 'evt-1',
      eventType: 'session',
      hostId: 'host-1',
      harnessId: 'harness-1',
      sourceProjectId: 'sp-1',
      startedAt: Date.parse(ISO),
      endedAt: null,
      parentId: null,
      rootSessionId: null,
    });
    expect(row.attributes).toBe(JSON.stringify({ os_version: '25.5.0' }));
  });

  it('toClassifiedDataRow keys by class only (no secret content)', () => {
    const row = toClassifiedDataRow({ class: 'aws_key', label: 'AWS key' }, 'cd-id');
    expect(row).toMatchObject({
      id: 'cd-id',
      class: 'aws_key',
      label: 'AWS key',
    });
    expect(row.attributes).toBeNull();
  });

  it('toInspectionDefinitionRow carries the rule version identity', () => {
    const row = toInspectionDefinitionRow(
      {
        ruleId: 'secrets/aws-access-key',
        version: '1.0.0',
        name: 'AWS access key',
        category: 'secret',
        severity: 'critical',
        definition: '{"matcher":"regex"}',
      },
      'def-id',
    );
    expect(row).toMatchObject({
      id: 'def-id',
      ruleId: 'secrets/aws-access-key',
      version: '1.0.0',
      category: 'secret',
      severity: 'critical',
    });
  });

  it('toInspectionFindingRow splits the span and never carries a raw match', () => {
    const row = toInspectionFindingRow({
      id: 'find-1',
      auditEventId: 'evt-1',
      inspectionDefinitionId: 'def-1',
      classifiedDataId: 'cd-1',
      span: { start: 3, end: 9 },
      maskedMatch: 'AKIA****',
      actionTaken: 'block',
      confidence: 0.99,
    });
    expect(row).toMatchObject({
      id: 'find-1',
      auditEventId: 'evt-1',
      inspectionDefinitionId: 'def-1',
      classifiedDataId: 'cd-1',
      spanStart: 3,
      spanEnd: 9,
      maskedMatch: 'AKIA****',
      actionTaken: 'block',
      confidence: 0.99,
    });
    expect(JSON.stringify(row)).not.toContain('rawMatch');
  });
});
