// The apply_patch field mapping rests on what a live Codex actually sends, so
// it is checked against payloads recorded from one (test/fixtures/hooks/, see
// the README there for the codex-cli version and what was rewritten). A Codex
// release that moved the patch text to another key would otherwise leave the
// hook finding no scannable field and exiting silently, with every test that
// builds its own payload still green.
import { readFileSync } from 'node:fs';

import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { decidePreToolUse, SCANNABLE_FIELDS } from '../../src/hooks/pre-tool-use-decision.ts';
import { collectResponseFields } from '../../src/hooks/tool-response.ts';

interface RecordedPayload {
  hook_event_name: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_response?: unknown;
}

function recorded(name: string): RecordedPayload {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/hooks/${name}`, import.meta.url), 'utf8'),
  ) as RecordedPayload;
}

const pre = recorded('apply_patch.pre-tool-use.json');
const post = recorded('apply_patch.post-tool-use.json');

describe('recorded apply_patch PreToolUse payload', () => {
  it('is the event and tool the mapping is keyed on', () => {
    expect(pre.hook_event_name).toBe('PreToolUse');
    expect(pre.tool_name).toBe('apply_patch');
  });

  it('carries the patch text under every field SCANNABLE_FIELDS names for it', () => {
    const specs = SCANNABLE_FIELDS[pre.tool_name] ?? [];
    expect(specs.length).toBeGreaterThan(0);
    for (const { field } of specs) {
      const value = pre.tool_input[field];
      expect(typeof value, field).toBe('string');
      expect(value, field).toMatch(/^\*\*\* Begin Patch\n[\s\S]*\*\*\* End Patch$/);
    }
    // And nothing else: a second key would be text the mapping does not scan.
    expect(Object.keys(pre.tool_input)).toEqual(specs.map((s) => s.field));
  });

  it('redacts in place inside the recorded input shape', () => {
    const [spec] = SCANNABLE_FIELDS[pre.tool_name] ?? [];
    if (!spec) throw new Error('apply_patch has no scannable field');
    const patch = pre.tool_input[spec.field] as string;
    const result: CaptureResult = {
      action: 'redact',
      text: patch.replace('hello from the patch', '[REDACTED:PII]'),
      findings: [
        {
          ruleId: 'core-pii/email',
          category: 'pii',
          severity: 'medium',
          span: { start: 0, end: 1 },
          rawMatch: 'h',
          confidence: 1,
        },
      ],
    };
    const output = decidePreToolUse(pre.tool_name, pre.tool_input, [{ spec, result }]);
    if (!output || !('hookSpecificOutput' in output)) throw new Error('expected a decision');
    expect(output.hookSpecificOutput.permissionDecision).toBe('allow');
    if (output.hookSpecificOutput.permissionDecision !== 'allow') return;
    expect(Object.keys(output.hookSpecificOutput.updatedInput)).toEqual(
      Object.keys(pre.tool_input),
    );
    expect(output.hookSpecificOutput.updatedInput[spec.field]).toContain('[REDACTED:PII]');
  });
});

describe('recorded apply_patch PostToolUse payload', () => {
  it('sends the same input and a plain-string result', () => {
    expect(post.hook_event_name).toBe('PostToolUse');
    expect(post.tool_input).toEqual(pre.tool_input);
    expect(typeof post.tool_response).toBe('string');
  });

  it('scans the result string whole', () => {
    expect(collectResponseFields(post.tool_name, post.tool_response).fields).toEqual([
      { path: [], text: post.tool_response },
    ]);
  });
});
