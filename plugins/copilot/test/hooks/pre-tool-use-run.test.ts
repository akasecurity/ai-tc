/**
 * The tool-call handler, driven in-process against a real temp home.
 *
 * What this file pins is RULE SELECTION per field. The command-risk rules are
 * scoped to `tool_use` captures and judge text about to run, so they belong on
 * a call's `command` and nowhere else on it. The model's prose beside the
 * command — the CLI's `bash.description`, VS Code's
 * `run_in_terminal.explanation` — rides along with the same capture kind, and
 * a sentence that merely MENTIONS reading a credential file must not deny a
 * call whose command is clean. Secret rules still run on that prose.
 *
 * Nothing is mocked but stderr, which is captured: the store is a real
 * `node:sqlite` file under a throwaway `akaHome`, and every payload is a
 * recorded fixture with its arguments and `cwd` re-pointed.
 */
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');

function fixture(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, path), 'utf8')) as Record<string, unknown>;
}

const SECRET_RULE = 'secrets/twilio-key';
const COMMAND_RULE = 'command-risk/credential-file-read';

/** The pack a bundled rule ships in, and the rule's first example. */
function bundledRule(ruleId: string): { namespace: string; packId: string; example: string } {
  // Taken from the rule's own examples rather than written here: this
  // repository is public, and a credential-shaped literal does not belong in it.
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === ruleId));
  const example = pack?.rules.find((r) => r.id === ruleId)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${ruleId} is missing from the pack registry or has no example`);
  }
  return { namespace: pack.namespace, packId: pack.packId, example };
}
const TWILIO_RULE = bundledRule(SECRET_RULE);
const COMMAND = bundledRule(COMMAND_RULE);

const PROSE = 'tail .env to check the prefix';
const CLEAN_COMMAND = 'git status';
const RISKY_COMMAND = 'tail .env';

const DIALECTS = [
  {
    kind: 'cli',
    event: 'preToolUse',
    proseField: 'description',
    payload: (command: string, prose: string, cwd: string): Record<string, unknown> => {
      const base = fixture('cli/preToolUse.json');
      return {
        ...base,
        cwd,
        toolArgs: { ...(base.toolArgs as object), command, description: prose },
      };
    },
    denied: (output: unknown): boolean =>
      (output as { permissionDecision?: unknown } | undefined)?.permissionDecision === 'deny',
  },
  {
    kind: 'vscode',
    event: 'PreToolUse',
    proseField: 'explanation',
    payload: (command: string, prose: string, cwd: string): Record<string, unknown> => {
      const base = fixture('vscode/plugin-load-1.141/preToolUse-run_in_terminal.json');
      return {
        ...base,
        cwd,
        tool_input: { ...(base.tool_input as object), command, explanation: prose },
      };
    },
    denied: (output: unknown): boolean =>
      (output as { hookSpecificOutput?: { permissionDecision?: unknown } } | undefined)
        ?.hookSpecificOutput?.permissionDecision === 'deny',
  },
] as const;

let root: string;
let akaHome: string;
let cwd: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-copilot-call-run-'));
  akaHome = join(root, 'aka-home');
  cwd = join(root, 'checkout');
  mkdirSync(join(cwd, '.git'), { recursive: true });
  writeFileSync(
    join(cwd, '.git', 'config'),
    '[remote "origin"]\n\turl = https://github.com/acme/work-repo.git\n',
  );
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  removeTrees([root]);
});

/** Blocks on both packs, so a command-risk finding is a deny rather than a warn. */
function seedPolicy(policy: BuiltinPolicyId): void {
  const db = openLocalDatabase(join(akaHome, 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(COMMAND.namespace, COMMAND.packId, policy);
    db.installedPacks.setPolicy(TWILIO_RULE.namespace, TWILIO_RULE.packId, policy);
  } finally {
    db.close();
  }
}

function foundRules(): string[] {
  const db = new DatabaseSync(join(akaHome, 'data', 'aka.db'), { readOnly: true });
  try {
    return db
      .prepare(
        `SELECT d.rule_id FROM inspection_findings f
           JOIN inspection_definitions d ON d.id = f.inspection_definition_id`,
      )
      .all()
      .map((row) => String(row.rule_id))
      .sort();
  } finally {
    db.close();
  }
}

describe.each(DIALECTS)('runPreToolUse rule selection on the $kind dialect', (d) => {
  async function run(command: string, prose: string): Promise<unknown> {
    return runPreToolUse(d.event, JSON.stringify(d.payload(command, prose, cwd)), { akaHome });
  }

  it(`does not deny a clean command over a ${d.proseField} that names a credential read`, async () => {
    seedPolicy('block');
    const output = await run(CLEAN_COMMAND, PROSE);

    expect(d.denied(output)).toBe(false);
    expect(output).toBeUndefined();
    expect(foundRules()).toEqual([]);
  });

  it('denies the same credential read when it is the command', async () => {
    // The positive control for the case above: the prose text really is what
    // the command-risk rule matches, so its silence there is rule selection.
    seedPolicy('block');
    const output = await run(RISKY_COMMAND, 'Show the first lines of the env file');

    expect(d.denied(output)).toBe(true);
    expect(foundRules()).toEqual([COMMAND_RULE]);
  });

  it(`still finds a secret in the ${d.proseField}`, async () => {
    seedPolicy('block');
    const output = await run(CLEAN_COMMAND, `${PROSE} TWILIO=${TWILIO_RULE.example}`);

    // The secret rule fires on the prose and the command-risk rule does not,
    // on one and the same field.
    expect(foundRules()).toEqual([SECRET_RULE]);
    expect(d.denied(output)).toBe(true);
  });
});
