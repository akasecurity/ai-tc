// The two fixture directories make DIFFERENT claims, and the whole value of
// keeping them apart is that a reader can tell which claim they are looking at.
//
//   test/fixtures/cli/                 recordings from a live Copilot CLI 1.0.83
//   test/fixtures/vscode-provisional/  a transcription of vendor documentation
//
// The failure this guards is not a wrong fixture. It is a doc-derived payload
// drifting into `cli/` — where every later reader, and every test that says
// "driven from the live recordings", silently starts treating an assumption as
// evidence. Nothing about such a file looks wrong; it is well-formed JSON in the
// right shape in the right place.
//
// So each directory is held to its own README, and the READMEs are held to
// saying the opposite things they are for.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { detectDialect, readToolCall } from '../src/hooks/dialect.ts';
import { isHookEventName } from '../src/hooks/event-name.ts';
import { scannableFields } from '../src/hooks/pre-tool-use-decision.ts';

const CLI_DIR = fileURLToPath(new URL('./fixtures/cli/', import.meta.url));
const VSCODE_DIR = fileURLToPath(new URL('./fixtures/vscode-provisional/', import.meta.url));

const jsonFiles = (dir: string): string[] =>
  readdirSync(dir)
    .filter((n) => n.endsWith('.json'))
    .sort();

const readme = (dir: string): string => readFileSync(join(dir, 'README.md'), 'utf8');

describe('the recordings in fixtures/cli', () => {
  const files = jsonFiles(CLI_DIR);

  it('are described, one paragraph per file, by their own README', () => {
    // A recording with nothing written about its capture is the shape a
    // doc-derived payload takes when it is moved across — it arrives with no
    // provenance, because it has none. The README is the authority on this
    // host anywhere in the repo, so a file it does not mention is a file
    // nobody has claimed was recorded.
    expect(files.length).toBeGreaterThan(0);
    const note = readme(CLI_DIR);
    for (const name of files) {
      const event = name.replace(/\.json$/, '');
      expect(note, `${name} is not described in fixtures/cli/README.md`).toContain(event);
    }
  });

  it('are claimed as recordings, with the capture conditions named', () => {
    // The positive control on the case above. Without it, a README emptied of
    // everything but a list of filenames would still satisfy the containment
    // check while claiming nothing at all about where the files came from.
    const note = readme(CLI_DIR);
    expect(note).toContain('1.0.83');
    expect(note).toContain('$COPILOT_HOME');
    expect(note).toMatch(/recorded shapes/i);
  });

  it('every one of them parses, carries the CLI envelope, and reads as the cli dialect', () => {
    for (const name of files) {
      const payload = JSON.parse(readFileSync(join(CLI_DIR, name), 'utf8')) as Record<
        string,
        unknown
      >;
      expect(detectDialect(payload), name).toBe('cli');
      expect(typeof payload.sessionId, name).toBe('string');
      expect(typeof payload.timestamp, name).toBe('number');
    }
  });

  it('are named for events the dispatcher knows', () => {
    for (const name of files) {
      expect(isHookEventName(name.replace(/\.json$/, '')), name).toBe(true);
    }
  });
});

describe('the transcriptions in fixtures/vscode-provisional', () => {
  const files = jsonFiles(VSCODE_DIR);

  it('say in their README that nothing here was recorded', () => {
    // This is the sentence that keeps the directory honest, and it is the one
    // most likely to be quietly softened once the VS Code half is shipping
    // code. Both halves are required: that no session produced these, AND that
    // the field table was NOT derived from them — which is the plan ordering
    // this work did not follow, recorded rather than glossed.
    const note = readme(VSCODE_DIR);
    expect(note).toContain('No live VS Code session produced any file in this directory');
    expect(note).toMatch(/PROVISIONAL, not recorded/);
    expect(note).toMatch(/not evidence of anything/);
  });

  it('are named for events the dispatcher knows, and read as the vscode dialect', () => {
    expect(files.length).toBeGreaterThan(0);
    for (const name of files) {
      const event = name.replace(/\.json$/, '');
      expect(isHookEventName(event), name).toBe(true);
      const payload = JSON.parse(readFileSync(join(VSCODE_DIR, name), 'utf8')) as Record<
        string,
        unknown
      >;
      expect(detectDialect(payload), name).toBe('vscode');
      // `hook_event_name` is the field the dialect detector tests first, and
      // the one the vendor documents as present on every event. A fixture that
      // disagreed with its own filename would make every case driven from it
      // describe a different event than it is named for.
      expect(payload.hook_event_name, name).toBe(event);
    }
  });

  it('cover every event name the dispatcher accepts for this host', () => {
    // Not a completeness claim about the host — a completeness claim about the
    // directory. A dispatcher that grows an event with no fixture is the state
    // where "built to the published contract" stops being checkable at all.
    const covered = files.map((n) => n.replace(/\.json$/, '')).sort();
    expect(covered).toEqual(
      [
        'PostToolUse',
        'PreCompact',
        'PreToolUse',
        'SessionStart',
        'Stop',
        'SubagentStart',
        'SubagentStop',
        'UserPromptSubmit',
      ].sort(),
    );
  });

  it('keep the PreToolUse fixture and the VS Code field table in step', () => {
    // These two have one source and one author, so this is a fixed point
    // rather than corroboration — see the directory's README, which says so
    // plainly. What it buys is that a change to either side now has to move the
    // other, instead of the table drifting off the only written record of what
    // it was built against.
    const payload = JSON.parse(readFileSync(join(VSCODE_DIR, 'PreToolUse.json'), 'utf8')) as Record<
      string,
      unknown
    >;
    const call = readToolCall(payload, 'vscode');
    expect(call).toBeDefined();
    const fields = scannableFields('vscode')[call?.name ?? ''];
    expect(fields, `no field table for ${call?.name ?? '(none)'}`).toBeDefined();
    for (const spec of fields ?? []) {
      expect(call?.args, `${spec.field} is in the table and not in the fixture`).toHaveProperty(
        spec.field,
      );
    }
  });
});

describe('the two directories stay distinguishable', () => {
  it('share no filename', () => {
    // The two vocabularies are camelCase and PascalCase, so an overlap means
    // one side has picked up the other's spelling — which is how a transcription
    // ends up filed as a recording.
    const cli = new Set(jsonFiles(CLI_DIR));
    for (const name of jsonFiles(VSCODE_DIR)) expect(cli.has(name), name).toBe(false);
  });

  it('never carry the other dialect’s envelope', () => {
    // The check that would catch a file physically moved between the two: a
    // payload's dialect is a property of its bytes, not of its directory.
    for (const name of jsonFiles(CLI_DIR)) {
      const payload = JSON.parse(readFileSync(join(CLI_DIR, name), 'utf8')) as Record<
        string,
        unknown
      >;
      expect(payload.hook_event_name, name).toBeUndefined();
    }
    for (const name of jsonFiles(VSCODE_DIR)) {
      const payload = JSON.parse(readFileSync(join(VSCODE_DIR, name), 'utf8')) as Record<
        string,
        unknown
      >;
      expect(payload.sessionId, name).toBeUndefined();
    }
  });
});
