import { describe, expect, it } from 'vitest';

import { parseStopPayload } from '../../src/hooks/stop-payload.ts';

describe('parseStopPayload', () => {
  it('extracts session_id + transcript_path from a well-formed Stop payload', () => {
    const trigger = parseStopPayload({
      session_id: 'sess-abc',
      transcript_path: '/home/me/.claude/projects/p/sess-abc.jsonl',
      cwd: '/home/me/proj',
      hook_event_name: 'Stop',
      stop_hook_active: false,
    });
    expect(trigger).toEqual({
      sessionId: 'sess-abc',
      transcriptPath: '/home/me/.claude/projects/p/sess-abc.jsonl',
    });
  });

  it('returns undefined (fail-open) when transcript_path is missing', () => {
    expect(parseStopPayload({ session_id: 'sess-abc' })).toBeUndefined();
  });

  it('returns undefined (fail-open) when session_id is missing', () => {
    expect(parseStopPayload({ transcript_path: '/x.jsonl' })).toBeUndefined();
  });

  it('returns undefined for a null payload (unparseable stdin) without throwing', () => {
    expect(() => parseStopPayload(null)).not.toThrow();
    expect(parseStopPayload(null)).toBeUndefined();
  });

  it('returns undefined when a field is the wrong type (non-string)', () => {
    expect(parseStopPayload({ session_id: 123, transcript_path: '/x.jsonl' })).toBeUndefined();
    expect(parseStopPayload({ session_id: 's', transcript_path: ['x'] })).toBeUndefined();
  });
});
