// Antigravity names the reconcile fields `conversationId` / `transcriptPath`
// (camelCase), where Claude Code and Codex send `session_id` /
// `transcript_path`. Both Stop and PostToolUse carry them, so one parser serves
// both entries — these cases pin the field names, because reading the
// snake_case ones would silently disable every reconcile on this host.
import { describe, expect, it } from 'vitest';

import { parseReconcileTrigger } from '../../src/hooks/stop-payload.ts';

const TRANSCRIPT = '/home/me/.gemini/brain/conv-abc/.system_generated/logs/transcript.jsonl';

describe('parseReconcileTrigger', () => {
  it('extracts conversationId + transcriptPath from a well-formed Stop payload', () => {
    const trigger = parseReconcileTrigger({
      executionNum: 1,
      terminationReason: 'completed',
      fullyIdle: true,
      conversationId: 'conv-abc',
      workspacePaths: ['/home/me/proj'],
      transcriptPath: TRANSCRIPT,
      artifactDirectoryPath: '/home/me/.gemini/brain/conv-abc/artifacts',
    });
    expect(trigger).toEqual({ sessionId: 'conv-abc', transcriptPath: TRANSCRIPT });
  });

  it('extracts the same pair from a PostToolUse payload', () => {
    const trigger = parseReconcileTrigger({
      toolCall: { name: 'run_command', args: { CommandLine: 'ls' } },
      stepIdx: 3,
      conversationId: 'conv-xyz',
      workspacePaths: ['/w'],
      transcriptPath: TRANSCRIPT,
    });
    expect(trigger).toEqual({ sessionId: 'conv-xyz', transcriptPath: TRANSCRIPT });
  });

  it('ignores the Claude Code / Codex snake_case spellings', () => {
    // Not a style preference: this host sends only the camelCase pair, so
    // accepting the snake_case one would mean a payload shaped like a sibling
    // harness's reconciled a path Antigravity never named.
    expect(
      parseReconcileTrigger({ session_id: 'sess-abc', transcript_path: TRANSCRIPT }),
    ).toBeUndefined();
  });

  it('returns undefined (fail-open) when transcriptPath is missing', () => {
    expect(parseReconcileTrigger({ conversationId: 'conv-abc' })).toBeUndefined();
  });

  it('returns undefined (fail-open) when conversationId is missing', () => {
    expect(parseReconcileTrigger({ transcriptPath: TRANSCRIPT })).toBeUndefined();
  });

  it('returns undefined for a null payload (unparseable stdin) without throwing', () => {
    expect(() => parseReconcileTrigger(null)).not.toThrow();
    expect(parseReconcileTrigger(null)).toBeUndefined();
  });

  it('returns undefined when a field is the wrong type (non-string)', () => {
    expect(
      parseReconcileTrigger({ conversationId: 123, transcriptPath: TRANSCRIPT }),
    ).toBeUndefined();
    expect(parseReconcileTrigger({ conversationId: 'c', transcriptPath: ['x'] })).toBeUndefined();
  });
});
