/**
 * `preToolUse` and `permissionRequest` BOTH fire for one tool call, in that
 * order, even under `--allow-all` — 41 ms apart in the recordings. So this host
 * offers two places to scan one call, and scanning both would record the same
 * tool use twice while enforcing on each half separately.
 *
 * The scan point is `preToolUse`, and it is not a coin toss:
 * `permissionRequest.toolInput` is a STRICT SUBSET of `preToolUse.toolArgs`. It
 * carries `command` alone, while `toolArgs` also carries `description` — the
 * model-authored prose this package's CLI field table scans and can redact in
 * place, because unlike the command it does not execute. A hook that scanned
 * `permissionRequest` instead would therefore miss a whole scannable field and
 * report success, which is the failure this file exists to make loud.
 *
 * Everything below is driven from the two recordings and from the manifest,
 * never from that paragraph.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { readToolCall } from '../../src/hooks/dialect.ts';
import { CLI_SCANNABLE_FIELDS } from '../../src/hooks/pre-tool-use-decision.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = join(HERE, '..', '..');
const FIXTURES = join(PLUGIN_ROOT, 'test', 'fixtures', 'cli');

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as Record<string, unknown>;
}

interface Manifest {
  hooks?: Record<string, { hooks?: { command?: string }[] }[]>;
}

/** Every script the manifest routes an event to. */
function scriptsFor(event: string): string[] {
  const manifest = JSON.parse(readFileSync(join(PLUGIN_ROOT, 'hooks.json'), 'utf8')) as Manifest;
  return (manifest.hooks?.[event] ?? []).flatMap((matcher) =>
    (matcher.hooks ?? []).map(
      (command) => /\/scripts\/([A-Za-z0-9-]+\.js)/.exec(command.command ?? '')?.[1] ?? '',
    ),
  );
}

describe('one tool call, one scan point', () => {
  // The premise, from the recordings' own timestamps rather than from prose:
  // both events really do fire for the one call, in this order.
  it('is a real collision — both events are recorded for the same call', () => {
    const pre = fixture('preToolUse.json');
    const permission = fixture('permissionRequest.json');
    expect(permission.sessionId).toBe(pre.sessionId);
    expect(permission.toolName).toBe(pre.toolName);
    expect(permission.timestamp as number).toBeGreaterThan(pre.timestamp as number);
  });

  it('routes the scanning script to preToolUse and to nothing else', () => {
    expect(scriptsFor('preToolUse')).toContain('pre-tool-use.js');
    // The whole point: no entry anywhere may send permissionRequest to it.
    expect(scriptsFor('permissionRequest')).not.toContain('pre-tool-use.js');
  });

  /**
   * WHY preToolUse and not permissionRequest, asserted against the field table
   * rather than restated. `description` is scannable, non-executable, and
   * present on only one of the two payloads.
   */
  it('reaches a field on preToolUse that permissionRequest does not carry', () => {
    const scannable = CLI_SCANNABLE_FIELDS.bash;
    expect(scannable).toBeDefined();
    const names = (scannable ?? []).map((spec) => spec.field);
    expect(names).toContain('description');

    const toolArgs = fixture('preToolUse.json').toolArgs as Record<string, unknown>;
    const toolInput = fixture('permissionRequest.json').toolInput as Record<string, unknown>;

    // A strict subset: every key of the permission payload is in the pre one,
    // and at least one scannable key is missing from it.
    for (const key of Object.keys(toolInput)) expect(Object.keys(toolArgs)).toContain(key);
    expect(Object.keys(toolInput)).not.toContain('description');
    expect(Object.keys(toolArgs)).toContain('description');
    expect(names.filter((name) => !Object.hasOwn(toolInput, name))).not.toHaveLength(0);
  });

  /**
   * The structural backstop, and the reason a mis-routed entry would be quiet
   * rather than loud: the CLI envelope reader looks for `toolArgs`, which a
   * `permissionRequest` payload does not have. So the call would be read with
   * an EMPTY argument bag — every scannable field skipped, no finding, an
   * explicit allow emitted, and a clean run reported.
   */
  it('would scan nothing at all if a permissionRequest payload reached the reader', () => {
    const call = readToolCall(fixture('permissionRequest.json'), 'cli');
    expect(call?.name).toBe('bash');
    expect(call?.args).toEqual({});

    // The control: the event this package DOES scan reads its arguments.
    const real = readToolCall(fixture('preToolUse.json'), 'cli');
    expect(Object.keys(real?.args ?? {})).toContain('command');
  });
});
