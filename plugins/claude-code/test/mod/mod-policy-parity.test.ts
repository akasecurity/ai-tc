import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  buildModPolicySnapshot,
  modPolicySnapshotPath,
  openLocalDatabase,
  readModPolicySnapshot,
} from '@akasecurity/persistence';
import { modPolicyInputFromBundle, StandaloneDataGateway } from '@akasecurity/plugin-runtime';
import { bundledDetections, createPluginRuntime } from '@akasecurity/plugin-sdk';
import type { InstalledPackInput } from '@akasecurity/schema';
import { Rule, SOURCE_TOOL, WorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { decideUserPromptSubmit } from '../../src/hooks/user-prompt-submit-decision.ts';

// The guard that the two policy paths never diverge. The UserPromptSubmit
// command hook reads the policy through the runtime and the standalone gateway;
// the mod reads the snapshot the store layer writes beside it. For each policy
// below, over the same store, the prompt the mod would hand the model must be
// the prompt the command hook's capture decides on: the redacted text where the
// hook's verdict is redact, and the prompt untouched under every other verdict.

const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

interface ModEngine {
  parseModPolicy: (text: string) => unknown;
  redactPromptWith: (text: string, policy: unknown) => string;
}

async function loadEngine(): Promise<ModEngine> {
  return (await import(pathToFileURL(join(PLUGIN_ROOT, 'hooks', 'engine.js')).href)) as ModEngine;
}

// The values come from bundled rules' own examples, so no secret-shaped literal
// lives in this file.
function example(ruleId: string): string {
  const value = bundledDetections()
    .flatMap((p) => p.rules)
    .find((r) => r.id === ruleId)?.examples?.[0];
  if (value === undefined) throw new Error(`bundled rule ${ruleId} has no example`);
  return value;
}

const SECRET = example('secrets/twilio-key');
const EMAIL = example('core-pii/email');
const TICKET = 'ACME-123456';

const TICKET_PACK: InstalledPackInput = {
  namespace: 'acme',
  packId: 'tickets',
  version: '1.0.0',
  name: 'Acme tickets',
  rules: [
    Rule.parse({
      specVersion: 1,
      id: 'acme/ticket',
      name: 'Acme ticket',
      category: 'custom',
      severity: 'high',
      matcher: { type: 'regex', pattern: 'ACME-[0-9]{6}', flags: 'g' },
      examples: [TICKET],
    }),
  ],
};

const PROMPTS = [
  `deploy with ${SECRET} please`,
  `mail ${EMAIL} about the rollout`,
  `mail ${EMAIL} and deploy with ${SECRET}`,
  `see ${TICKET} before ${SECRET}`,
  `see ${TICKET}`,
  'rename this variable across the module',
];

type Store = ReturnType<typeof openLocalDatabase>;

interface PolicyCase {
  name: string;
  apply: (db: Store) => void;
}

const CASES: PolicyCase[] = [
  { name: 'the bundled defaults', apply: () => undefined },
  {
    name: 'a category set to redact',
    apply: (db) => {
      db.policies.upsertCategoryAction('pii', 'redact');
    },
  },
  {
    name: 'a category set to block over a pack set to redact',
    apply: (db) => {
      db.policies.upsertCategoryAction('secret', 'block');
      db.installedPacks.setPolicy('aka', 'secrets', 'redact');
    },
  },
  {
    name: 'a user-modified pack: one pack to redact, another to block',
    apply: (db) => {
      db.installedPacks.setPolicy('aka', 'secrets', 'redact');
      db.installedPacks.setPolicy('aka', 'core-pii', 'block');
    },
  },
  {
    name: 'a pack set to redact and then back to monitor',
    apply: (db) => {
      db.installedPacks.setPolicy('aka', 'secrets', 'redact');
      db.installedPacks.setPolicy('aka', 'secrets', 'monitor');
    },
  },
  {
    name: 'a pack switched off under a redacting category',
    apply: (db) => {
      db.policies.upsertCategoryAction('secret', 'redact');
      db.installedPacks.setEnabled('aka', 'secrets', false);
    },
  },
  {
    name: 'a custom pack under a redact policy',
    apply: (db) => {
      db.installedPacks.recordInventory([...bundledDetections(), TICKET_PACK]);
      db.installedPacks.setPolicy('acme', 'tickets', 'redact');
    },
  },
  {
    name: 'a custom pack under a block policy beside a redacting category',
    apply: (db) => {
      db.installedPacks.recordInventory([...bundledDetections(), TICKET_PACK]);
      db.installedPacks.setPolicy('acme', 'tickets', 'block');
      db.policies.upsertCategoryAction('secret', 'redact');
    },
  },
];

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-mod-parity-'));
});

afterEach(() => {
  removeTree(dir);
});

// What the command hook decides on a prompt: the runtime's capture over the
// standalone gateway, which is where the hook gets its policy.
async function hookText(prompt: string): Promise<string> {
  const gateway = new StandaloneDataGateway(dir, bundledDetections());
  const runtime = createPluginRuntime(gateway, WorkspaceSettings.parse({}), { dataDir: dir });
  try {
    const result = await runtime.capture({
      kind: 'prompt',
      sourceTool: SOURCE_TOOL.ClaudeCode,
      text: prompt,
      metadata: undefined,
    });
    // The hook blocks a redact (it cannot rewrite the prompt), and the block's
    // rewrite is the same text the capture redacts to.
    const decision = await decideUserPromptSubmit(prompt, result);
    if (result.action === 'redact') {
      expect(decision).toMatchObject({ decision: 'block' });
      return result.text ?? prompt;
    }
    return prompt;
  } finally {
    await runtime.close();
  }
}

describe('the mod reaches the command hook verdict from the snapshot', () => {
  it.each(CASES)('$name', async ({ apply }) => {
    // Opening the gateway records the inventory, as every hook does.
    const gateway = new StandaloneDataGateway(dir, bundledDetections());
    await gateway.close();
    const db = openLocalDatabase(dir);
    try {
      apply(db);
    } finally {
      db.close();
    }

    const engine = await loadEngine();
    const policy = engine.parseModPolicy(readFileSync(modPolicySnapshotPath(dir), 'utf8'));
    expect(policy).not.toBeNull();
    for (const prompt of PROMPTS) {
      expect(engine.redactPromptWith(prompt, policy)).toBe(await hookText(prompt));
    }
  });

  it.each(CASES)('$name: the store and the gateway write the same snapshot', async ({ apply }) => {
    const gateway = new StandaloneDataGateway(dir, bundledDetections());
    const db = openLocalDatabase(dir);
    try {
      apply(db);
    } finally {
      db.close();
    }
    const fromStore = readModPolicySnapshot(dir);
    const fromGateway = buildModPolicySnapshot(
      modPolicyInputFromBundle(await gateway.getPolicyBundle()),
    );
    await gateway.close();

    expect(fromStore).not.toBeNull();
    expect({ ...fromStore, generatedAt: '' }).toEqual({ ...fromGateway, generatedAt: '' });
  });

  it('some case redacts, so the comparison is not vacuous', async () => {
    const gateway = new StandaloneDataGateway(dir, bundledDetections());
    await gateway.close();
    const db = openLocalDatabase(dir);
    try {
      db.installedPacks.setPolicy('aka', 'secrets', 'redact');
    } finally {
      db.close();
    }
    expect(await hookText(`deploy with ${SECRET} please`)).toContain('[REDACTED:SECRET]');
  });
});
