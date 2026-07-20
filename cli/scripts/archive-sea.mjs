// Archive the packaged SEA binary + its sidecars into a distributable tarball (unix) or
// zip (Windows), and emit the archive's SHA-256. Run after `package:sea`. Output:
//   sea-dist/aka-<version>-<platform>-<arch>.(tar.gz|zip)  (+ a matching .sha256)
// The archive contains the `aka-<platform>-<arch>/` directory (binary + boot.cjs +
// cli.mjs + package.json + web-ui), so extracting yields a ready-to-run tree.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cliDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const { platform, arch } = process;
const isWin = platform === 'win32';
const triple = `${platform}-${arch}`;
const seaDist = join(cliDir, 'sea-dist');
const stagedName = `aka-${triple}`;
const stagedDir = join(seaDist, stagedName);
if (!existsSync(stagedDir)) {
  throw new Error(`missing ${stagedDir} — run \`pnpm package:sea\` first`);
}

const { version } = JSON.parse(readFileSync(join(cliDir, 'package.json'), 'utf8'));
const archiveName = `aka-${version}-${triple}.${isWin ? 'zip' : 'tar.gz'}`;
const archivePath = join(seaDist, archiveName);
rmSync(archivePath, { force: true });

if (isWin) {
  execFileSync(
    'powershell',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `Compress-Archive -Force -Path '${stagedDir}' -DestinationPath '${archivePath}'`,
    ],
    { stdio: 'inherit' },
  );
} else {
  execFileSync('tar', ['-czf', archivePath, '-C', seaDist, stagedName], { stdio: 'inherit' });
}

const sha = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
const line = `${sha}  ${archiveName}\n`;
writeFileSync(`${archivePath}.sha256`, line);
process.stdout.write(`archived: ${archivePath}\n${line}`);
