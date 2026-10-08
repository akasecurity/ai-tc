import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';

const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_FILE = join(PLUGIN_ROOT, 'hooks', 'engine.js');
const PARSED_ID = 'aka:parsed-packs';

// Phase 1 runs in Node: bundle a probe that parses every bundled rule with the
// real Rule schema and prints the result as JSON. BUNDLED_PACKS comes from the
// file scripts/gen-bundled-packs.mjs generates, so a rule added under rules/
// reaches the engine module with no edit here.
const PROBE = `
import { Rule } from '@akasecurity/schema';
import { BUNDLED_PACKS } from '../../packages/plugin-sdk/src/bundled-packs.generated.ts';
export default BUNDLED_PACKS.map((p) => ({
  packId: p.packId,
  rules: p.rawRules.map((raw) => Rule.parse(raw)),
}));
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

export async function buildEngine() {
  const packsJson = await parseBundledPacks();
  const result = await build({
    entryPoints: [join(PLUGIN_ROOT, 'src', 'mod', 'engine-entry.ts')],
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    mainFields: ['module', 'main'],
    target: 'es2022',
    minify: true,
    legalComments: 'none',
    metafile: true,
    write: false,
    outfile: OUT_FILE,
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
            contents: `export const PARSED_PACKS = ${packsJson};`,
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

  writeFileSync(OUT_FILE, text);
  return { file: OUT_FILE, bytes: statSync(OUT_FILE).size, source: readFileSync(OUT_FILE, 'utf8') };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { bytes } = await buildEngine();
  console.log(`hooks/engine.js ${bytes} bytes`);
}
