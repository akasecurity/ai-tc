// The pure half of the sessionStart hook. Never imports the entry file —
// src/hooks/*.ts entries run main() on import and would hang collection.
//
// Every payload here is a RECORDED fixture rather than a literal written to
// match the reader, for the reason `test/fixtures/vscode-provisional/README.md`
// gives: a reader tested against a fixture written from the reader proves only
// that the two agree with each other.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  harnessInterfaceFor,
  readSessionStartFacts,
} from '../../src/hooks/session-start-payload.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');

function fixture(dir: string, name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, dir, name), 'utf8')) as Record<string, unknown>;
}

describe('harnessInterfaceFor', () => {
  it('reports vscode for the VS Code dialect', () => {
    expect(harnessInterfaceFor('vscode')).toBe('vscode');
  });

  // THE CLI DIALECT COVERS TWO SURFACES and must report only one of them. A
  // terminal `copilot` and the cloud coding agent speak the same wire, so a
  // hook that answered 'cloud' for either would be writing a fabricated fact
  // onto a durable per-session row.
  it('reports cli for the CLI dialect, never cloud', () => {
    expect(harnessInterfaceFor('cli')).toBe('cli');
  });

  // No surface beats the wrong surface: this value is snapshotted onto the
  // session root and never revised.
  it('reports nothing when the dialect could not be told', () => {
    expect(harnessInterfaceFor(undefined)).toBeUndefined();
  });
});

describe('readSessionStartFacts', () => {
  it('reads the recorded CLI sessionStart payload', () => {
    const facts = readSessionStartFacts(fixture('cli', 'sessionStart.json'));
    expect(facts.dialect).toBe('cli');
    expect(facts.sessionId).toBe('c1779e76-9889-419b-ab12-f7bb8a957e15');
    expect(facts.cwd).toBe('/Users/dev/ai-tc');
    expect(facts.harnessInterface).toBe('cli');
  });

  it('reads the provisional VS Code SessionStart payload', () => {
    const facts = readSessionStartFacts(fixture('vscode-provisional', 'SessionStart.json'));
    expect(facts.dialect).toBe('vscode');
    expect(facts.sessionId).toBe('00000000-0000-4000-8000-000000000000');
    expect(facts.cwd).toBe('/Users/dev/ai-tc');
    expect(facts.harnessInterface).toBe('vscode');
  });

  // The two fixtures above spell the session id in DIFFERENT keys, and this is
  // what makes that pair discriminating rather than decorative: a reader that
  // resolved the dialect wrong — or that consumed its two parameters in the
  // other order — reads `sessionId` off the snake_case payload, finds nothing,
  // and lands every capture in that session with no session id at all. That
  // failure looks exactly like the defect this card is fixing, so it is stated
  // as its own case rather than left implicit in the two above.
  it('resolves each dialect to the key that dialect actually spells', () => {
    const cli = fixture('cli', 'sessionStart.json');
    const vscode = fixture('vscode-provisional', 'SessionStart.json');
    expect(cli.session_id).toBeUndefined();
    expect(vscode.sessionId).toBeUndefined();
    expect(readSessionStartFacts(cli).sessionId).toBe(cli.sessionId);
    expect(readSessionStartFacts(vscode).sessionId).toBe(vscode.session_id);
  });

  it('answers all-undefined for an unparseable payload', () => {
    expect(readSessionStartFacts(null)).toEqual({
      dialect: undefined,
      sessionId: undefined,
      cwd: undefined,
      harnessInterface: undefined,
    });
  });

  // The discriminating case for the CLI fallback: an envelope matching NEITHER
  // dialect still reads the CLI's way — a root opened under the right id is
  // worth more than a strict refusal — but it must NOT invent a surface for it.
  it('falls back to the CLI spelling on an unrecognised envelope, with no interface', () => {
    const facts = readSessionStartFacts({ sessionID: 'wrong-casing', cwd: '/w' });
    expect(facts.dialect).toBeUndefined();
    // `sessionID` is neither spelling, so nothing is resolved from it.
    expect(facts.sessionId).toBeUndefined();
    expect(facts.harnessInterface).toBeUndefined();
    // `cwd` is spelled the same way by both hosts, so it survives the fallback.
    expect(facts.cwd).toBe('/w');
  });

  // `cwd` is reported absent rather than defaulted, because the entry has to be
  // able to tell "no workspace" from "the home directory". Under VS Code the
  // spawn's own cwd IS the home directory, so a default here would silently
  // resolve a repo from `~`.
  it('reports an absent cwd rather than substituting one', () => {
    expect(readSessionStartFacts({ hook_event_name: 'SessionStart', session_id: 's' })).toEqual({
      dialect: 'vscode',
      sessionId: 's',
      cwd: undefined,
      harnessInterface: 'vscode',
    });
  });
});
