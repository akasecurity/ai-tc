/**
 * The Homebrew formula and Scoop manifest a binary release publishes, rendered
 * from that release's own SHA256SUMS.
 *
 * Everything here is pure: text in, text out. The entry beside it owns the
 * argv, the file read and the three writes, so every decision below is driven
 * directly by the suite.
 */

/** The platform triples the binary channel builds. */
export const TRIPLES = ['darwin-arm64', 'linux-x64', 'linux-arm64', 'win32-x64'] as const;

export type Triple = (typeof TRIPLES)[number];

/** The one sentence both manifests describe the tool with. */
export const DESC = 'Local-first security control plane for AI coding agents';

/** Homebrew refuses a `desc` longer than this. */
export const MAX_DESC_LENGTH = 80;

/** The SPDX identifier both manifests carry. */
export const LICENSE = 'Apache-2.0';

const BARE_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

const REPO = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;

// Lowercase only. `shasum` and `createHash().digest('hex')` both emit lowercase,
// so an uppercase or truncated hash in a sums file was written by hand rather
// than by the build that produced the archive it claims to describe.
const SHA256 = /^[0-9a-f]{64}$/;

const SUMS_LINE = /^([0-9a-fA-F]+)\s+\*?(\S.*)$/;

/** A refusal that names a bad input rather than a bug in this renderer. */
export class ManifestInputError extends Error {}

/** The tag every archive of one release hangs off. Immutable once pushed. */
export function downloadBase(repo: string, version: string): string {
  return `https://github.com/${repo}/releases/download/bin-v${version}`;
}

/** The moving tag the two version-tracking probes read. */
export function rollingBase(repo: string): string {
  return `https://github.com/${repo}/releases/download/bin-latest`;
}

/** The archive filename `cli/scripts/archive-sea.mjs` writes for a triple. */
export function assetName(version: string, triple: Triple): string {
  return `aka-${version}-${triple}.${triple.startsWith('win32') ? 'zip' : 'tar.gz'}`;
}

/** The single top-level directory that archive holds. */
export function extractDirName(triple: Triple): string {
  return `aka-${triple}`;
}

/** Refuses anything but a bare `X.Y.Z`; the binary channel publishes no others. */
export function assertBareVersion(version: string): string {
  if (!BARE_VERSION.test(version)) {
    throw new ManifestInputError(
      `version "${version}" is not a bare X.Y.Z — the binary channel publishes no pre-release tags`,
    );
  }
  return version;
}

/** Refuses anything but `owner/name`, which is all a download URL can carry. */
export function assertRepo(repo: string): string {
  if (!REPO.test(repo)) {
    throw new ManifestInputError(`repo "${repo}" is not <owner>/<name>`);
  }
  return repo;
}

/**
 * `<sha256>  <filename>` lines, keyed by filename.
 *
 * Refuses a line it cannot read, a hash that is not 64 lowercase hex, and a
 * filename listed twice — a duplicate leaves which hash describes the published
 * asset undecidable, and picking either one silently is the failure.
 */
export function parseSums(text: string): Map<string, string> {
  const out = new Map<string, string>();
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? '').trim();
    if (line === '') continue;
    const matched = SUMS_LINE.exec(line);
    if (matched === null) {
      throw new ManifestInputError(
        `SHA256SUMS line ${String(index + 1)} is not "<sha256>  <filename>"`,
      );
    }
    const hash = matched[1] ?? '';
    const file = matched[2] ?? '';
    if (!SHA256.test(hash)) {
      throw new ManifestInputError(
        `SHA256SUMS line ${String(index + 1)}: ${file} carries a hash that is not 64 lowercase hex characters`,
      );
    }
    if (out.has(file)) {
      throw new ManifestInputError(`SHA256SUMS lists ${file} twice`);
    }
    out.set(file, hash);
  }
  return out;
}

/**
 * The four archive hashes, keyed by triple.
 *
 * Every absent asset is collected before anything is thrown, so one missing
 * build does not hide the other three.
 */
export function archiveHashes(
  sums: ReadonlyMap<string, string>,
  version: string,
): Record<Triple, string> {
  const missing: string[] = [];
  const pick = (triple: Triple): string => {
    const name = assetName(version, triple);
    const hash = sums.get(name);
    if (hash === undefined) {
      missing.push(name);
      return '';
    }
    return hash;
  };
  const hashes: Record<Triple, string> = {
    'darwin-arm64': pick('darwin-arm64'),
    'linux-x64': pick('linux-x64'),
    'linux-arm64': pick('linux-arm64'),
    'win32-x64': pick('win32-x64'),
  };
  if (missing.length > 0) {
    throw new ManifestInputError(`SHA256SUMS is missing ${missing.join(' and ')}`);
  }
  return hashes;
}

/** What both renderers need to produce one release's manifests. */
export interface ManifestInput {
  version: string;
  repo: string;
  sums: ReadonlyMap<string, string>;
}

/**
 * The tap formula.
 *
 * `url` and `sha256` sit directly inside `on_macos` rather than in a nested
 * `on_arm`: a formula that resolves no url for the running platform fails to
 * load before it can explain itself, and there is no darwin-x64 archive to
 * offer an Intel Mac. `depends_on arch: :arm64` is what refuses that machine,
 * with a sentence naming the requirement.
 */
export function renderFormula(input: ManifestInput): string {
  const version = assertBareVersion(input.version);
  const repo = assertRepo(input.repo);
  const hashes = archiveHashes(input.sums, version);
  const base = downloadBase(repo, version);
  const rolling = rollingBase(repo);

  return [
    'class Aka < Formula',
    `  desc "${DESC}"`,
    `  homepage "https://github.com/${repo}"`,
    `  version "${version}"`,
    `  license "${LICENSE}"`,
    '',
    // Homebrew's component order puts livecheck ahead of every on_* block.
    '  livecheck do',
    `    url "${rolling}/VERSION"`,
    '    regex(/^(\\d+(?:\\.\\d+)+)$/i)',
    '    strategy :page_match',
    '  end',
    '',
    '  on_macos do',
    '    depends_on arch: :arm64',
    `    url "${base}/${assetName(version, 'darwin-arm64')}"`,
    `    sha256 "${hashes['darwin-arm64']}"`,
    '  end',
    '',
    '  on_linux do',
    '    on_arm do',
    // `on_arm` fires on 32-bit ARM as well, where this archive cannot exec.
    '      depends_on arch: :arm64',
    `      url "${base}/${assetName(version, 'linux-arm64')}"`,
    `      sha256 "${hashes['linux-arm64']}"`,
    '    end',
    '    on_intel do',
    `      url "${base}/${assetName(version, 'linux-x64')}"`,
    `      sha256 "${hashes['linux-x64']}"`,
    '    end',
    '  end',
    '',
    '  def install',
    // The archive holds one top-level directory, which Homebrew has already
    // chdir'd into. The binary resolves its sidecars from the directory its own
    // executable sits in, following symlinks, so it has to stay beside them and
    // be reached through a link rather than copied out on its own.
    '    libexec.install Dir["*"]',
    '    bin.install_symlink libexec/"aka"',
    '  end',
    '',
    '  def caveats',
    '    <<~EOS',
    '      Run `aka init` to create the local store under ~/.aka.',
    '    EOS',
    '  end',
    '',
    '  test do',
    '    assert_match version.to_s, shell_output("#{bin}/aka --version")',
    '  end',
    'end',
    '',
  ].join('\n');
}

/**
 * The bucket manifest.
 *
 * `$version` stays a literal token in both autoupdate URLs: Scoop substitutes
 * it when its excavator finds a newer version, and a concrete version baked in
 * there republishes this same release for ever.
 *
 * The autoupdate hash regex is written out rather than left to Scoop's default.
 * That default reads a file holding nothing but a hash; the filename-anchored
 * form is only a fallback, and a later match inside the same branch can
 * overwrite what it found.
 *
 * Scoop matches that regex once against the whole downloaded SHA256SUMS, with
 * no multiline option, so a bare `^` anchors at the file's first byte and never
 * reaches the Windows line. The `(?m:…)` group makes both anchors line anchors;
 * .NET and JavaScript read that group the same way.
 */
export function renderScoopManifest(input: ManifestInput): string {
  const version = assertBareVersion(input.version);
  const repo = assertRepo(input.repo);
  const hashes = archiveHashes(input.sums, version);
  const base = downloadBase(repo, version);
  const rolling = rollingBase(repo);
  const template = `https://github.com/${repo}/releases/download/bin-v$version`;

  const manifest = {
    version,
    description: DESC,
    homepage: `https://github.com/${repo}`,
    license: LICENSE,
    architecture: {
      '64bit': {
        url: `${base}/${assetName(version, 'win32-x64')}`,
        hash: hashes['win32-x64'],
        extract_dir: extractDirName('win32-x64'),
      },
    },
    bin: 'aka.exe',
    notes: 'Run `aka init` to create the local store under %USERPROFILE%\\.aka.',
    checkver: {
      url: `${rolling}/VERSION`,
      regex: '^([\\d.]+)$',
    },
    autoupdate: {
      architecture: {
        '64bit': {
          url: `${template}/aka-$version-win32-x64.zip`,
        },
      },
      hash: {
        url: `${template}/SHA256SUMS`,
        regex: '(?m:^([a-fA-F0-9]{64})\\s+aka-$version-win32-x64\\.zip$)',
      },
    },
  };

  return `${JSON.stringify(manifest, null, 2)}\n`;
}

/** What both version-tracking probes read off the rolling tag. */
export function renderVersionFile(version: string): string {
  return `${assertBareVersion(version)}\n`;
}
