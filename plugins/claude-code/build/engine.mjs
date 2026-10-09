import { Buffer } from 'node:buffer';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';

const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_FILE = join(PLUGIN_ROOT, 'hooks', 'engine.js');
const PARSED_ID = 'aka:parsed-packs';

// Phase 1 runs in Node: bundle a probe that parses every bundled rule with the
// real Rule schema and prints the result as JSON. BUNDLED_PACKS comes from the
// file scripts/gen-bundled-packs.mjs generates, so a rule added under rules/
// reaches the engine module with no edit here.
// It also resolves, through the real policy resolver, the action a fresh install
// enforces for each bundled rule: a pack that ships a defaultPolicy assigns it
// to every rule it carries (assignedRulePolicies), and every other rule falls
// to the category rows the local store seeds at Monitor ('log'). The mod ships
// that answer as data, so it never carries a second policy model.
const PROBE = `
import {
  DEFAULT_ACTIONS,
  POINTER_TOKEN_PATTERN,
  Rule,
  VAULT_INLINE_REVEAL_MAX_PER_MESSAGE,
  builtinPolicyToAction,
} from '@akasecurity/schema';
import { BUNDLED_PACKS } from '../../packages/plugin-sdk/src/bundled-packs.generated.ts';
import {
  assignedRulePolicies,
  createPolicyResolver,
} from '../../packages/plugin-sdk/src/policy-resolver.ts';

const packs = BUNDLED_PACKS.map((p) => ({
  packId: p.packId,
  defaultPolicy: p.defaultPolicy,
  rules: p.rawRules.map((raw) => Rule.parse(raw)),
}));

const ruleActions = new Map();
for (const p of packs) {
  if (p.defaultPolicy === undefined) continue;
  for (const r of p.rules) ruleActions.set(r.id, builtinPolicyToAction(p.defaultPolicy));
}
const resolver = createPolicyResolver({
  version: 'bundled-defaults',
  policies: [
    ...Object.keys(DEFAULT_ACTIONS).map((category) => ({
      id: 'seed-' + category,
      scope: 'global',
      target: { category },
      action: 'log',
      enabled: true,
    })),
    ...assignedRulePolicies({ ruleActions }),
  ],
  customKeywords: [],
  fetchedAt: '',
});
const actions = {};
for (const p of packs) {
  for (const r of p.rules) actions[r.id] = resolver.actionFor(r.id, r.category);
}

export default {
  packs: packs.map((p) => ({ packId: p.packId, rules: p.rules })),
  actions,
  pointerPattern: POINTER_TOKEN_PATTERN.source,
  revealCap: VAULT_INLINE_REVEAL_MAX_PER_MESSAGE,
};
`;

async function parseBundledPacks() {
  const probe = await build({
    stdin: { contents: PROBE, resolveDir: PLUGIN_ROOT, loader: 'ts' },
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'node',
    target: 'node24',
    logLevel: 'silent',
  });
  const code = probe.outputFiles[0].text;
  const mod = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
  // Plain JSON round trip: the mod gets data, and a non-serializable parse
  // result (a RegExp, a Date) fails here instead of silently becoming {}.
  const json = JSON.stringify(mod.default);
  if (JSON.stringify(JSON.parse(json)) !== json) throw new Error('parsed packs are not plain JSON');
  return json;
}

// `stdin` swaps the entry for generated source (the mod-runtime fixture wraps the
// real entry to inject failures); `outFile` redirects the write. Both default to
// the shipped build.
export async function buildEngine({ stdin, outFile = OUT_FILE } = {}) {
  const packsJson = await parseBundledPacks();
  const result = await build({
    ...(stdin === undefined
      ? { entryPoints: [join(PLUGIN_ROOT, 'src', 'mod', 'engine-entry.ts')] }
      : { stdin: { contents: stdin, resolveDir: PLUGIN_ROOT, loader: 'ts' } }),
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    mainFields: ['module', 'main'],
    target: 'es2022',
    minify: true,
    legalComments: 'none',
    metafile: true,
    write: false,
    outfile: outFile,
    logLevel: 'warning',
    plugins: [
      {
        name: 'aka-parsed-packs',
        setup(b) {
          b.onResolve({ filter: /^aka:parsed-packs$/ }, () => ({
            path: PARSED_ID,
            namespace: 'aka',
          }));
          b.onLoad({ filter: /.*/, namespace: 'aka' }, () => ({
            contents: `export const PARSED_DATA = ${packsJson};`,
            loader: 'js',
          }));
        },
      },
    ],
  });

  const [output] = result.outputFiles;
  const text = output.text;
  const meta = Object.values(result.metafile.outputs)[0];

  // Fail the build rather than ship a module the mod runtime cannot load.
  const problems = [];
  if (meta.imports.length > 0) {
    problems.push(
      `unbundled imports: ${meta.imports.map((i) => `${i.kind} ${i.path}`).join(', ')}`,
    );
  }
  if (/\b__require\b|\btypeof require\b/.test(text)) problems.push('require shim present');
  if (/(?:\bfrom|\bimport)\s*["']node:/.test(text)) problems.push('node: specifier');
  if (/\bimport\.meta\b/.test(text)) problems.push('import.meta');
  if (problems.length > 0) throw new Error(`engine.js is not mod-ready: ${problems.join('; ')}`);

  writeFileSync(outFile, text);
  return { file: outFile, bytes: statSync(outFile).size, source: readFileSync(outFile, 'utf8') };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { bytes } = await buildEngine();
  process.stdout.write(`hooks/engine.js ${String(bytes)} bytes\n`);
}
