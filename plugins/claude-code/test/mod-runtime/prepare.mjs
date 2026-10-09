import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';

import { buildEngine } from '../../build/engine.mjs';

// Stages what `claude plugin test` needs. A test file may only import from
// inside its plugin folder, so the built hooks/engine.js is copied in beside
// it, and the Node engine's answer for every rule fixture is written out as
// cases.generated.js for the in-runtime test to compare against. Both
// outputs are git-ignored.
//
// The fixture runs the shipped hooks/mod.ts verbatim. Only the engine beside it
// is a test build: it wraps the real entry's prompt rewrite to raise the fault
// the fail-open case needs. The product module carries no such switch, and the
// policy is the one the test answers from beneath, as the user's own would be.
const HERE = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = join(HERE, '..', '..');
const RULES_ROOT = join(PLUGIN_ROOT, '..', '..', 'rules');
const ENGINE = join(PLUGIN_ROOT, 'hooks', 'engine.js');

if (!existsSync(ENGINE)) throw new Error('hooks/engine.js is missing; run `pnpm build` first');
copyFileSync(join(PLUGIN_ROOT, 'hooks', 'mod.ts'), join(HERE, 'mod.ts'));

const TEST_ENGINE = `
  import { planPromptWith as realPlanPromptWith } from './src/mod/engine-entry.ts';
  import type { ModPolicy, PromptPlan } from './src/mod/engine-entry.ts';
  export * from './src/mod/engine-entry.ts';
  export function planPromptWith(text: string, policy: ModPolicy | null): PromptPlan {
    if (text.includes('__ENGINE_THROWS__')) throw new Error('injected engine fault');
    return realPlanPromptWith(text, policy);
  }
`;
await buildEngine({ stdin: TEST_ENGINE, outFile: join(HERE, 'engine.js') });

const probe = await build({
  stdin: {
    contents: `
      import { redact, scan } from '@akasecurity/detections';
      import { registerBundledPacks } from '@akasecurity/plugin-sdk';
      registerBundledPacks();
      export default (cases) => cases.map((c) => {
        const findings = scan(c.text, undefined, c.context);
        return {
          ...c,
          findings: findings.map((f) => ({ ruleId: f.ruleId, span: f.span })),
          redacted: redact(c.text, findings),
        };
      });
    `,
    resolveDir: PLUGIN_ROOT,
    loader: 'ts',
  },
  bundle: true,
  write: false,
  format: 'esm',
  platform: 'node',
  target: 'node24',
  logLevel: 'silent',
});
const nodeEngine = await import(
  `data:text/javascript;base64,${Buffer.from(probe.outputFiles[0].text).toString('base64')}`
);

// One bundled rule's own example stands in for a secret, so no secret-shaped
// literal lives in the test source.
const SAMPLE_RULE = 'secrets/twilio-key';
const sampleSecret = JSON.parse(
  readFileSync(join(RULES_ROOT, 'secrets', 'twilio-key.json'), 'utf8'),
).examples?.[0];
if (typeof sampleSecret !== 'string') throw new Error(`${SAMPLE_RULE} has no example`);
writeFileSync(
  join(HERE, 'samples.generated.js'),
  `export const SECRET = ${JSON.stringify(sampleSecret)};\n`,
);

const cases = [];
for (const pack of readdirSync(RULES_ROOT, { withFileTypes: true })) {
  const dir = join(RULES_ROOT, pack.name, 'fixtures');
  if (!pack.isDirectory() || !existsSync(dir)) continue;
  for (const name of readdirSync(dir).filter((n) => n.endsWith('.json'))) {
    for (const c of JSON.parse(readFileSync(join(dir, name), 'utf8'))) {
      cases.push({
        id: `${pack.name}/${name}: ${c.label}`,
        text: c.text,
        context: { filePath: c.filePath, eventKind: c.eventKind },
      });
    }
  }
}
writeFileSync(
  join(HERE, 'cases.generated.js'),
  `export default ${JSON.stringify(nodeEngine.default(cases))};\n`,
);
console.log(`staged engine.js and ${cases.length} cases`);
