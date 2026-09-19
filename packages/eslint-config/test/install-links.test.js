/**
 * README.md and cli/README.md both point at the binary release's Homebrew tap,
 * Scoop bucket, bootstrap one-liners and `bin-latest` download links. None of
 * those are checked by anything that reads a README as prose — a link is a
 * string that either resolves or does not, and nothing here renders a page.
 *
 * Every fact this suite compares against is DERIVED from the workflow and from
 * `install-channel.ts` rather than retyped, for the reason the workflow's own
 * `release-binaries-integrity.test.js` gives for its published/attested globs:
 * a hand-written mirror of a list is free to drift the moment the list it
 * copies changes, and it drifts silently because nothing points back at the
 * source it was copied from.
 *
 * - The alias archive names come from the rolling step's own `files:` block
 *   scalar, so a fifth build target's alias entry is picked up here without a
 *   second edit — and a README that was not updated to match it fails on the
 *   "every alias archive is linked" case below, not on a count that moved in
 *   step with it.
 * - The Homebrew/Scoop targets come from the two publish jobs' `TARGET_REPO`/
 *   `TARGET_PATH` env, so a retargeted tap or bucket reddens the README
 *   comparison instead of leaving two copies of the same string to disagree.
 * - The bootstrap one-liners come from `install-channel.ts`'s own
 *   `INSTALLER_SH`/`INSTALLER_PS1`, which is also what `aka update` tells a
 *   standalone install to re-run — so the README and the tool's own advice
 *   are held to the same string rather than to two.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import { blockScalarLines, jobBlock, stepNamed } from './helpers/workflow.js';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const WORKFLOW = join(REPO_ROOT, '.github', 'workflows', 'release-binaries.yml');
const INSTALL_CHANNEL = join(REPO_ROOT, 'packages', 'local-ops', 'src', 'install-channel.ts');
const README_PATHS = {
  'README.md': join(REPO_ROOT, 'README.md'),
  'cli/README.md': join(REPO_ROOT, 'cli', 'README.md'),
};
const INSTALLER_README = join(REPO_ROOT, 'tools', 'installer', 'README.md');

const readFile = (path) => readFileSync(path, 'utf8');
const readWorkflow = () => readFile(WORKFLOW);

const releaseJob = () => jobBlock(readWorkflow(), 'release');
const buildJob = () => jobBlock(readWorkflow(), 'build');
const rollingStep = () => stepNamed(releaseJob(), 'Publish the rolling bin-latest release');

/** The last `/`-separated segment of a path-like string. */
const basename = (path) => path.split('/').pop();

const BIN_LATEST_URL = 'https://github.com/akasecurity/ai-tc/releases/download/bin-latest/';

/**
 * Every asset the rolling release publishes, as basenames — the alias
 * archives plus the checksum file and the two rendered package-manager
 * manifests and VERSION. Read from the step's own `files:` rather than a
 * literal, so an asset added or renamed there is what every case below
 * reacts to.
 */
function rollingAssets() {
  const entries = blockScalarLines(rollingStep(), 'files');
  expect(
    entries.filter((entry) => entry.includes('*')),
    'the rolling step names a glob — a glob covers whatever a directory holds, ' +
      'not the fixed set of names a download link can point at',
  ).toEqual([]);
  return entries.map(basename);
}

/** The alias ARCHIVES alone — a renamed `.tar.gz` or `.zip`, never the sums file or a manifest. */
const aliasArchives = () => rollingAssets().filter((name) => /\.(?:tar\.gz|zip)$/.test(name));

/**
 * How many targets the build fan-out produces, read from the matrix's own
 * `target:` entries. This is the positive control for the archive count
 * below: a fifth platform added to the matrix (and staged as a fifth alias
 * archive) is what has to move this number, or the count comparison would
 * pass by coincidence rather than by tracking the same fan-out.
 */
function matrixTargetCount() {
  const matches = [
    ...buildJob().matchAll(/^[^\S\n]*-[^\S\n]*\{[^}]*\btarget:[^\S\n]*([a-z0-9-]+)/gm),
  ];
  expect(matches.length, 'the build job matrix declares no target').toBeGreaterThan(0);
  return matches.length;
}

/**
 * The `TARGET_REPO`/`TARGET_PATH` a publish job pushes to, read from its own
 * `env:` block. Both are asserted to appear exactly once in the job body so a
 * job carrying two conflicting values (one per step) cannot answer for
 * "the" target.
 */
function publishTarget(jobId) {
  const body = jobBlock(readWorkflow(), jobId);
  const repos = [...body.matchAll(/^[^\S\n]*TARGET_REPO:[^\S\n]*(\S+)[^\S\n]*$/gm)].map(
    (m) => m[1],
  );
  const paths = [...body.matchAll(/^[^\S\n]*TARGET_PATH:[^\S\n]*(\S+)[^\S\n]*$/gm)].map(
    (m) => m[1],
  );
  expect(repos.length, `\`${jobId}\` declares no TARGET_REPO`).toBeGreaterThan(0);
  expect(new Set(repos).size, `\`${jobId}\`'s steps disagree about TARGET_REPO`).toBe(1);
  expect(paths.length, `\`${jobId}\` declares no TARGET_PATH`).toBeGreaterThan(0);
  expect(new Set(paths).size, `\`${jobId}\`'s steps disagree about TARGET_PATH`).toBe(1);
  return { repo: repos[0], path: paths[0] };
}

/**
 * The `brew install <owner>/<tap>/<formula>` command a tap's `TARGET_REPO`/
 * `TARGET_PATH` resolves to. Homebrew addresses a `homebrew-<name>` repository
 * by its bare `<name>`, and the formula is the `.rb` file's own basename.
 */
function brewCommand({ repo, path }) {
  const [owner, tapRepo] = repo.split('/');
  expect(tapRepo, `\`${repo}\` is not an <owner>/<repo> tap target`).toMatch(/^homebrew-/);
  const alias = tapRepo.replace(/^homebrew-/, '');
  const formula = basename(path).replace(/\.rb$/, '');
  return `brew install ${owner}/${alias}/${formula}`;
}

/** The URL `scoop bucket add <name> <url>` names for a bucket's own `TARGET_REPO`. */
const bucketUrl = ({ repo }) => `https://github.com/${repo}`;

/**
 * The `scoop bucket add <name> <url>` command a bucket's own `TARGET_REPO`
 * resolves to — the bucket is added under its owner's name, exactly as the
 * README does today.
 */
const scoopCommand = (target) =>
  `scoop bucket add ${target.repo.split('/')[0]} ${bucketUrl(target)}`;

/** Every `brew install <owner>/<tap>/<formula>` command a text carries, verbatim. */
const brewCommands = (text) => [...text.matchAll(/\bbrew install \S+/g)].map((m) => m[0]);

/** Every `scoop bucket add <name> <url>` command a text carries, verbatim. */
const scoopCommands = (text) => [...text.matchAll(/\bscoop bucket add \S+ \S+/g)].map((m) => m[0]);

/**
 * Every `raw.githubusercontent.com/.../install.(sh|ps1)` URL a text carries —
 * the bootstrap one-liners' download target, and nothing else that domain
 * might be linked for.
 */
const rawInstallerUrls = (text) =>
  [...text.matchAll(/https:\/\/raw\.githubusercontent\.com\/\S+/g)]
    .map((m) => m[0])
    .filter((url) => /\/install\.(?:sh|ps1)$/.test(url));

/** The `raw.githubusercontent.com/.../install.(sh|ps1)` URL inside a one-liner command. */
function rawUrlOf(command, label) {
  const match = /https:\/\/raw\.githubusercontent\.com\/\S+/.exec(command);
  expect(
    match,
    `install-channel.ts's ${label} carries no raw.githubusercontent.com URL`,
  ).not.toBeNull();
  return match[0];
}

/** Every `<name>` this text links under `releases/download/bin-latest/`. */
function binLatestLinkedNames(text) {
  return [...text.matchAll(/releases\/download\/bin-latest\/([A-Za-z0-9._-]+)/g)].map((m) => m[1]);
}

/** The value of a `const <name> = '…';` declaration, tolerating the value on its own line. */
function stringConstant(source, name) {
  const match = new RegExp(`const ${name} =[^\\S\\n]*\\n?[^\\S\\n]*'([^']+)';`).exec(source);
  expect(match, `install-channel.ts declares no ${name}`).not.toBeNull();
  expect(match[1], `install-channel.ts's ${name} is empty`).not.toBe('');
  return match[1];
}

const README_ENTRIES = Object.entries(README_PATHS);

describe('the rolling release archives every README links', () => {
  it('stages at least one archive, and as many as the build matrix produces (positive control)', () => {
    const archives = aliasArchives();
    expect(archives.length).toBeGreaterThan(0);
    expect(archives.length).toBe(matrixTargetCount());
  });

  it.each(README_ENTRIES)('%s links every alias archive the rolling step stages', (name, path) => {
    const text = readFile(path);
    for (const archive of aliasArchives()) {
      expect(text, `${name} carries no link to ${archive}`).toContain(
        `${BIN_LATEST_URL}${archive}`,
      );
    }
  });

  it.each(README_ENTRIES)(
    '%s names no bin-latest asset the rolling step does not stage',
    (name, path) => {
      const text = readFile(path);
      const linked = binLatestLinkedNames(text);
      expect(
        linked.length,
        `${name} carries no releases/download/bin-latest/ link at all`,
      ).toBeGreaterThan(0);
      const assets = rollingAssets();
      expect(
        linked.filter((linkedName) => !assets.includes(linkedName)),
        `${name} links a bin-latest asset the rolling step never stages`,
      ).toEqual([]);
    },
  );
});

describe('README install commands agree with the workflow they describe', () => {
  // Derived in a hook rather than in the describe body: these helpers assert,
  // and an assertion at collection time is a collection error that reports the
  // whole FILE as "no tests" instead of failing the cases that depend on it.
  /** @type {string} */
  let BREW_COMMAND;
  /** @type {string} */
  let BUCKET_URL;
  /** @type {string} */
  let SCOOP_COMMAND;
  /** @type {string} */
  let INSTALLER_SH;
  /** @type {string} */
  let INSTALLER_PS1;
  /** @type {string} */
  let INSTALLER_SH_URL;
  /** @type {string} */
  let INSTALLER_PS1_URL;
  beforeAll(() => {
    const scoopTarget = publishTarget('publish-scoop-bucket');
    BREW_COMMAND = brewCommand(publishTarget('publish-homebrew-tap'));
    BUCKET_URL = bucketUrl(scoopTarget);
    SCOOP_COMMAND = scoopCommand(scoopTarget);
    const installChannel = readFile(INSTALL_CHANNEL);
    INSTALLER_SH = stringConstant(installChannel, 'INSTALLER_SH');
    INSTALLER_PS1 = stringConstant(installChannel, 'INSTALLER_PS1');
    INSTALLER_SH_URL = rawUrlOf(INSTALLER_SH, 'INSTALLER_SH');
    INSTALLER_PS1_URL = rawUrlOf(INSTALLER_PS1, 'INSTALLER_PS1');
  });

  it('derives a non-empty brew command and bucket URL (positive control)', () => {
    expect(BREW_COMMAND).not.toBe('');
    expect(BUCKET_URL).not.toBe('');
    expect(SCOOP_COMMAND).not.toBe('');
    expect(INSTALLER_SH_URL).not.toBe('');
    expect(INSTALLER_PS1_URL).not.toBe('');
  });

  it.each(README_ENTRIES)(
    '%s carries the brew command the workflow actually publishes to',
    (name, path) => {
      expect(readFile(path), `${name} does not contain \`${BREW_COMMAND}\``).toContain(
        BREW_COMMAND,
      );
    },
  );

  it.each(README_ENTRIES)(
    '%s carries the scoop bucket URL the workflow actually publishes to',
    (name, path) => {
      expect(readFile(path), `${name} does not contain ${BUCKET_URL}`).toContain(BUCKET_URL);
    },
  );

  it.each(README_ENTRIES)(
    '%s carries the install.sh one-liner install-channel.ts advises',
    (name, path) => {
      expect(readFile(path), `${name} does not contain the INSTALLER_SH one-liner`).toContain(
        INSTALLER_SH,
      );
    },
  );

  it.each(README_ENTRIES)(
    '%s carries the install.ps1 one-liner install-channel.ts advises',
    (name, path) => {
      expect(readFile(path), `${name} does not contain the INSTALLER_PS1 one-liner`).toContain(
        INSTALLER_PS1,
      );
    },
  );

  // The four cases above are "is the derived string present somewhere" —
  // satisfied by a README that keeps a STALE command alongside the current
  // one, which is exactly the shape a retargeted tap or bucket leaves behind
  // if only the new spelling is added. Mirrored here in the other direction,
  // the way the alias-archive case above already reads both ways: every
  // command of that SHAPE the README carries must be the one the workflow
  // actually publishes to, not merely include it somewhere.
  it.each(README_ENTRIES)(
    '%s names no brew tap other than the one the workflow publishes to',
    (name, path) => {
      const commands = brewCommands(readFile(path));
      expect(
        commands,
        `${name} carries no \`brew install\` command at all (positive control)`,
      ).not.toHaveLength(0);
      expect(
        commands.filter((c) => c !== BREW_COMMAND),
        `${name} carries a \`brew install\` command other than \`${BREW_COMMAND}\``,
      ).toEqual([]);
    },
  );

  it.each(README_ENTRIES)(
    '%s names no scoop bucket other than the one the workflow publishes to',
    (name, path) => {
      const commands = scoopCommands(readFile(path));
      expect(
        commands,
        `${name} carries no \`scoop bucket add\` command at all (positive control)`,
      ).not.toHaveLength(0);
      expect(
        commands.filter((c) => c !== SCOOP_COMMAND),
        `${name} carries a \`scoop bucket add\` command other than \`${SCOOP_COMMAND}\``,
      ).toEqual([]);
    },
  );

  it.each(README_ENTRIES)(
    '%s links no raw.githubusercontent.com install script other than the derived ones',
    (name, path) => {
      const urls = rawInstallerUrls(readFile(path));
      expect(
        urls,
        `${name} carries no raw.githubusercontent.com install.{sh,ps1} URL at all (positive control)`,
      ).not.toHaveLength(0);
      expect(
        urls.filter((url) => url !== INSTALLER_SH_URL && url !== INSTALLER_PS1_URL),
        `${name} links a raw.githubusercontent.com install script other than ${INSTALLER_SH_URL} or ` +
          INSTALLER_PS1_URL,
      ).toEqual([]);
    },
  );
});

// Kept identical to plugins/claude-code/test/privacy-claims.test.ts's LOCALITY_CLAIM
// (also copied, for the same reason, into privacy-claim-coverage.test.js): an
// absolute claim that data stays on the machine needs the `[^egress]` footnote
// attached in the same paragraph, and the new prose here carries neither the
// claim nor the footnote.
const LOCALITY_CLAIM =
  /nothing (?:leaves|is sent)|never (?:leaves|send)|not sent to a model|no scanning happens off|scanned off your/i;

/**
 * Text from just after `heading` up to the next markdown heading, or the end
 * of the file. A heading line is only recognised OUTSIDE a fenced code block —
 * this section's own bootstrap one-liners carry `# macOS / Linux` and
 * `# or, without adding the bucket:` shell comments that also match
 * `#{1,6} `, and treating those as headings closed the section right after
 * the Scoop block, silently exempting everything after it (the whole
 * download table, the Intel macOS note and the upgrade line) from the
 * locality check below.
 */
function sectionAfter(text, heading) {
  const start = text.indexOf(heading);
  expect(start, `could not find "${heading}"`).toBeGreaterThanOrEqual(0);
  const rest = text.slice(start + heading.length);
  const lines = rest.split('\n');
  let inFence = false;
  let endLine = lines.length;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('```') || line.startsWith('~~~')) {
      inFence = !inFence;
      continue;
    }
    if (!inFence && /^#{1,6} /.test(line)) {
      endLine = i;
      break;
    }
  }
  return lines.slice(0, endLine).join('\n');
}

describe('the new install prose carries no locality claim', () => {
  it("README.md's new CLI subsection", () => {
    const section = sectionAfter(
      readFile(README_PATHS['README.md']),
      '### The `aka` CLI (standalone binary)',
    );
    expect(section).not.toMatch(LOCALITY_CLAIM);
  });

  it("cli/README.md's rewritten Install section", () => {
    const section = sectionAfter(readFile(README_PATHS['cli/README.md']), '## Install');
    expect(section).not.toMatch(LOCALITY_CLAIM);
  });

  // tools/installer/README.md is not one of privacy-claims.test.ts's classified
  // front doors, and privacy-claim-coverage.test.js requires that set to be
  // exact — so unlike the two README rows above, this page may carry the
  // pattern nowhere at all, not merely outside its new section.
  it('tools/installer/README.md, anywhere in the file', () => {
    expect(readFile(INSTALLER_README)).not.toMatch(LOCALITY_CLAIM);
  });
});
