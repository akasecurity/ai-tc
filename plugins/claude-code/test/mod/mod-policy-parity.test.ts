import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  buildModPolicySnapshot,
  modPolicySnapshotPath,
  openLocalDatabase,
  readModPolicySnapshot,
} from '@akasecurity/persistence';
import {
  modPolicyInputFromBundle,
  StandaloneDataGateway,
  syncModPolicySnapshot,
} from '@akasecurity/plugin-runtime';
import {
  bundledDetections,
  createPluginRuntime,
  shippedRegexMatchers,
} from '@akasecurity/plugin-sdk';
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

// A custom pack arrives as an installed row only: the available mirror holds
// what the binary ships and nothing else.
function installCustomPack(): void {
  const raw = new DatabaseSync(join(dir, 'aka.db'));
  try {
    raw
      .prepare(
        `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, policy_id, created_at, updated_at)
         VALUES (:id, :namespace, :packId, :version, :name, :rulesJson, 1, NULL, 1, 1)`,
      )
      .run({
        id: 'custom-tickets',
        namespace: TICKET_PACK.namespace,
        packId: TICKET_PACK.packId,
        version: TICKET_PACK.version,
        name: TICKET_PACK.name,
        rulesJson: JSON.stringify(TICKET_PACK.rules),
      });
  } finally {
    raw.close();
  }
}

const PROMPTS = [
  `deploy with ${SECRET} please`,
  `mail ${EMAIL} about the rollout`,
  `mail ${EMAIL} and deploy with ${SECRET}`,
  `see ${TICKET} before ${SECRET}`,
  `see ${TICKET}`,
  'rename this variable across the module',
];

type Store = ReturnType<typeof openLocalDatabase>;

// The store as the plugin opens it: told which patterns this build ships, which is
// what lets the snapshot carry the bundled regex rules without a timing verdict.
const SHIPPED = { shippedRegexMatchers: shippedRegexMatchers() };

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
      installCustomPack();
      db.installedPacks.setPolicy('acme', 'tickets', 'redact');
    },
  },
  {
    name: 'a custom pack under a block policy beside a redacting category',
    apply: (db) => {
      installCustomPack();
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
    const db = openLocalDatabase(dir, SHIPPED);
    try {
      apply(db);
    } finally {
      db.close();
    }

    // SessionStart vets the rules a custom pack adds (timed where it can be
    // killed) and writes the snapshot from the effective bundle.
    const session = new StandaloneDataGateway(dir, bundledDetections());
    await syncModPolicySnapshot(session, dir);
    await session.close();

    const engine = await loadEngine();
    const policy = engine.parseModPolicy(readFileSync(modPolicySnapshotPath(dir), 'utf8'));
    expect(policy).not.toBeNull();
    for (const prompt of PROMPTS) {
      expect(engine.redactPromptWith(prompt, policy)).toBe(await hookText(prompt));
    }
  });

  it('a custom rule not yet vetted stays out of the mod, and the command hook still enforces it', async () => {
    const gateway = new StandaloneDataGateway(dir, bundledDetections());
    await gateway.close();
    const db = openLocalDatabase(dir, SHIPPED);
    try {
      installCustomPack();
      db.installedPacks.setPolicy('acme', 'tickets', 'redact');
    } finally {
      db.close();
    }

    const engine = await loadEngine();
    const policy = engine.parseModPolicy(readFileSync(modPolicySnapshotPath(dir), 'utf8'));
    const prompt = `see ${TICKET}`;

    // The store wrote the snapshot without the unvetted pattern, so the mod leaves
    // the prompt as typed ...
    expect(engine.redactPromptWith(prompt, policy)).toBe(prompt);
    // ... and the hook, which scans under a deadline, still redacts (blocks) it.
    expect(await hookText(prompt)).not.toContain(TICKET);
  });

  it.each(CASES.filter((c) => !c.name.startsWith('a custom pack')))(
    '$name: the store and the gateway write the same snapshot',
    async ({ apply }) => {
      const gateway = new StandaloneDataGateway(dir, bundledDetections());
      const db = openLocalDatabase(dir, SHIPPED);
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
    },
  );

  it('some case redacts, so the comparison is not vacuous', async () => {
    const gateway = new StandaloneDataGateway(dir, bundledDetections());
    await gateway.close();
    const db = openLocalDatabase(dir, SHIPPED);
    try {
      db.installedPacks.setPolicy('aka', 'secrets', 'redact');
    } finally {
      db.close();
    }
    expect(await hookText(`deploy with ${SECRET} please`)).toContain('[REDACTED:SECRET]');
  });
});
