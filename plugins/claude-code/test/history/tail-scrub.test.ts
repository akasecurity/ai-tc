import { randomUUID } from 'node:crypto';
import {
  appendFileSync,
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyOnboarding } from '@akasecurity/persistence';
import {
  createPolicyResolver,
  createVaultGlue,
  type PolicyResolver,
  type VaultGlue,
} from '@akasecurity/plugin-sdk';
import type { ActionTaken, PolicyBundle } from '@akasecurity/schema';
import { pointerTokenScanner, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree, removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { scrubTranscriptTail, type TailScrubDeps } from '../../src/history/tail-scrub.ts';
import type { RedactionScope } from '../../src/remediation/redact.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// Canonical test AWS access-key id, composed at runtime so the repo's own secret
// scan does not flag this test file (mirrors remediation/redact.test.ts).
const SECRET = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
// A second, DIFFERENT bundled detection over the same text, so a policy that
// governs one of them can be shown not to govern the other in the same file.
// Composed at runtime for the same reason SECRET is.
const MONITORED = ['someone', 'mail.invalid'].join('@');
const AWS_RULE = 'secrets/aws-access-key';
const MONITORED_RULE = 'core-pii/email';

const pointersIn = (text: string): string[] =>
  [...text.matchAll(pointerTokenScanner())].map((m) => m[0]);

describe('scrubTranscriptTail', () => {
  // A fake transcripts root (the scope's one artifact root), an out-of-scope
  // sibling, and a throwaway ~/.aka base holding the real vault.
  let transcriptRoot: string;
  let outsideRoot: string;
  let base: string;
  let scope: RedactionScope;
  let glue: VaultGlue;
  let deps: TailScrubDeps;

  const depsFor = (g: VaultGlue): TailScrubDeps => ({
    tokenizeText: (text) => g.tokenizeText(text),
    scope,
  });

  beforeEach(() => {
    transcriptRoot = mkdtempSync(join(tmpdir(), 'aka-tail-scrub-transcripts-'));
    outsideRoot = mkdtempSync(join(tmpdir(), 'aka-tail-scrub-outside-'));
    base = mkdtempSync(join(tmpdir(), 'aka-tail-scrub-home-'));
    scope = { artifactRoots: [transcriptRoot] };
    applyOnboarding(
      {
        vaultConsent: {
          acknowledgedAt: new Date().toISOString(),
          version: VAULT_CONSENT_VERSION,
        },
      },
      base,
    );
    glue = createVaultGlue({ base });
    deps = depsFor(glue);
  });

  afterEach(() => {
    removeTrees([transcriptRoot, outsideRoot, base]);
  });

  const transcriptFile = (name: string, content: string): string => {
    const dir = join(transcriptRoot, '-Users-me-project');
    mkdirSync(dir, { recursive: true });
    const file = join(dir, name);
    writeFileSync(file, content);
    return file;
  };

  it('rewrites the secret line to a vault pointer and leaves the clean line byte-identical', async () => {
    const secretLine = `{"type":"user","text":"key ${SECRET} end"}`;
    const cleanLine = '{"type":"assistant","text":"all clear"}';
    const file = transcriptFile('session.jsonl', `${secretLine}\n${cleanLine}\n`);

    const result = await scrubTranscriptTail(file, deps);
    expect(result).toEqual({ rewritten: 1 });

    const after = readFileSync(file, 'utf8');
    // Positive control on the same bytes first: an absence assertion over a
    // file the scrub never wrote would pass without proving anything.
    expect(after).toContain('[[aka:');
    expectNoEchoOf(after, SECRET);
    expect(after.endsWith('\n')).toBe(true);

    const lines = after.split('\n');
    expect(lines).toHaveLength(3); // two records + trailing-newline terminator
    expect(lines[1]).toBe(cleanLine);
    expect(lines[2]).toBe('');

    // The secret span became a pointer, embedded in still-valid NDJSON.
    expect(pointersIn(lines[0] ?? '')).toHaveLength(1);
    for (const line of lines.slice(0, 2)) {
      expect(() => {
        JSON.parse(line);
      }).not.toThrow();
    }
    const parsed = JSON.parse(lines[0] ?? '') as { text: string };
    expect(parsed.text).toContain('[[aka:');
  });

  it('mints the SAME pointer for the same value across two lines', async () => {
    const file = transcriptFile(
      'repeat.jsonl',
      `{"text":"first ${SECRET}"}\n{"text":"again ${SECRET}"}\n`,
    );

    const result = await scrubTranscriptTail(file, deps);
    expect(result).toEqual({ rewritten: 2 });

    const [a, b] = readFileSync(file, 'utf8').split('\n');
    const pa = pointersIn(a ?? '');
    const pb = pointersIn(b ?? '');
    expect(pa).toHaveLength(1);
    expect(pb).toHaveLength(1);
    expect(pa[0]).toBe(pb[0]);
  });

  it('is idempotent: a second run rewrites nothing and leaves the file byte-identical', async () => {
    const file = transcriptFile('idem.jsonl', `{"text":"key ${SECRET}"}\n`);
    expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 1 });

    const afterFirst = readFileSync(file, 'utf8');
    expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 0 });
    expect(readFileSync(file, 'utf8')).toBe(afterFirst);
  });

  it('returns { rewritten: 0 } without writing when the file holds no secret', async () => {
    const content = '{"text":"nothing sensitive here"}\n';
    const file = transcriptFile('clean.jsonl', content);
    expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 0 });
    expect(readFileSync(file, 'utf8')).toBe(content);
  });

  it('refuses an out-of-scope path and leaves it byte-identical', async () => {
    const content = `{"text":"key ${SECRET}"}\n`;
    const outside = join(outsideRoot, 'not-a-transcript.jsonl');
    writeFileSync(outside, content);

    expect(await scrubTranscriptTail(outside, deps)).toBeNull();
    expect(readFileSync(outside, 'utf8')).toBe(content);
  });

  it('refuses a symlink inside the root that points outside it', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    const content = `{"text":"key ${SECRET}"}\n`;
    const target = join(outsideRoot, 'target.jsonl');
    writeFileSync(target, content);
    const link = join(transcriptRoot, 'link.jsonl');
    symlinkSync(target, link);

    expect(await scrubTranscriptTail(link, deps)).toBeNull();
    expect(readFileSync(target, 'utf8')).toBe(content);
  });

  it('returns null for an unreadable path without throwing', async () => {
    expect(await scrubTranscriptTail(join(transcriptRoot, 'missing.jsonl'), deps)).toBeNull();
  });

  it('aborts on the unclassifiable blanket: changed text with no pointers and no degraded spans', async () => {
    const content = `{"text":"key ${SECRET}"}\n`;
    const file = transcriptFile('blanket.jsonl', content);
    // A tokenizer that rewrites the line but mints no pointer and degrades no
    // span cannot tell secret from clean — honouring it would blanket-destroy
    // transcript lines, so the scrub must abort with the file untouched.
    const blanketDeps: TailScrubDeps = {
      tokenizeText: () =>
        Promise.resolve({
          text: '[REDACTED-EVERYTHING]',
          pointers: [],
          degraded: [],
          redacted: [],
        }),
      scope,
    };

    expect(await scrubTranscriptTail(file, blanketDeps)).toBeNull();
    expect(readFileSync(file, 'utf8')).toBe(content);
  });

  it('skips a file larger than the configured byte cap, leaving it untouched', async () => {
    const content = `{"text":"key ${SECRET}"}\n`;
    const file = transcriptFile('oversized.jsonl', content);

    expect(await scrubTranscriptTail(file, { ...deps, maxBytes: 8 })).toBeNull();
    expect(readFileSync(file, 'utf8')).toBe(content);
  });

  it('aborts when the live transcript grew mid-scrub, keeping the appended lines intact', async () => {
    const original = `{"text":"key ${SECRET}"}\n`;
    const appended = '{"text":"appended while the scrub was tokenizing"}\n';
    const file = transcriptFile('race.jsonl', original);
    // A tokenizer that appends to the file mid-scrub, simulating Claude Code
    // writing to the live transcript while the scrub works on its in-memory
    // snapshot. Renaming the snapshot over the grown file would silently
    // destroy the appended line, so the scrub must abort instead.
    const racingDeps: TailScrubDeps = {
      tokenizeText: (text) => {
        appendFileSync(file, appended);
        return Promise.resolve({
          text: text.split(SECRET).join('[[aka:secret:RACE]]'),
          pointers: ['[[aka:secret:RACE]]'],
          degraded: [],
          redacted: [],
        });
      },
      scope,
    };

    expect(await scrubTranscriptTail(file, racingDeps)).toBeNull();
    // The post-append content — including the line the snapshot never saw —
    // survives, and no tmp orphan remains.
    expect(readFileSync(file, 'utf8')).toBe(original + appended);
    const siblings = readdirSync(join(transcriptRoot, '-Users-me-project'));
    expect(siblings.filter((entry) => entry.endsWith('.aka-scrub.tmp'))).toEqual([]);
  });

  it.runIf(process.platform !== 'win32')(
    'preserves a 0600 transcript mode across the rewrite',
    async () => {
      const file = transcriptFile('mode.jsonl', `{"text":"key ${SECRET}"}\n`);
      chmodSync(file, 0o600);

      expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 1 });

      // The rewrite lands via a fresh temp file; without an explicit mode it
      // would widen the 0600 transcript to the umask default.
      expect(statSync(file).mode & 0o777).toBe(0o600);
      const after = readFileSync(file, 'utf8');
      expect(after).toContain('[[aka:');
      expectNoEchoOf(after, SECRET);
    },
  );

  // The fault posture when consent vanished mid-pass (the call site gates on
  // consent, so a consent-less glue is only reachable via revocation between
  // the gate and the scrub): the residue is destroyed one-way — rewritten, but
  // to the un-recoverable placeholder, never left raw and never vaulted.
  it('degrades one-way under a consent-less glue: redacted placeholder, no pointer', async () => {
    const noConsentBase = mkdtempSync(join(tmpdir(), 'aka-tail-scrub-noconsent-'));
    try {
      const degradedGlue = createVaultGlue({ base: noConsentBase });
      const file = transcriptFile('degraded.jsonl', `{"text":"key ${SECRET}"}\n`);

      expect(await scrubTranscriptTail(file, depsFor(degradedGlue))).toEqual({ rewritten: 1 });

      const after = readFileSync(file, 'utf8');
      expect(after).toContain('[REDACTED');
      expectNoEchoOf(after, SECRET);
      expect(after).not.toContain('[[aka:');
    } finally {
      removeTree(noConsentBase);
    }
  });

  it('does not abort a changed line the tokenizer reports as struck by policy', async () => {
    const content = `{"text":"key ${SECRET}"}\n`;
    const file = transcriptFile('policy-struck.jsonl', content);
    // The same SHAPE as the blanket above — changed text, no pointer, no
    // degraded span — but accounted for: the tokenizer says it struck the span
    // because policy assigned Redact rather than Redact & Vault. Reading only
    // the first two counts would abandon a file on every line policy correctly
    // rewrote.
    const struckDeps: TailScrubDeps = {
      tokenizeText: () =>
        Promise.resolve({
          text: '{"text":"key [REDACTED:SECRET]"}',
          pointers: [],
          degraded: [],
          redacted: [{ category: 'secret' }],
        }),
      scope,
    };

    expect(await scrubTranscriptTail(file, struckDeps)).toEqual({ rewritten: 1 });
    expect(readFileSync(file, 'utf8')).toBe('{"text":"key [REDACTED:SECRET]"}\n');
  });

  // The policy half of the scrub. The scrub carries no findings of its own, so
  // the glue self-scans — and an unnarrowed self-scan rewrites and vaults every
  // span the bundled rules match, including one whose detection the user only
  // ever asked to monitor. Each case below drives ONE file holding both a
  // governed and an ungoverned value, so a "left alone" assertion can never
  // pass because the second rule simply never fired.
  describe('under a pack policy', () => {
    const bundleWith = (
      actions: Readonly<Record<string, ActionTaken>>,
      reversibleRuleIds: string[],
    ): PolicyBundle => ({
      version: 'test',
      policies: Object.entries(actions).map(([ruleId, action]) => ({
        id: randomUUID(),
        scope: 'global',
        target: { ruleId },
        action,
        enabled: true,
      })),
      reversibleRuleIds,
      rules: [],
      customKeywords: [],
      fetchedAt: new Date().toISOString(),
    });

    const depsWith = (resolver: PolicyResolver): TailScrubDeps => ({
      tokenizeText: (text) => glue.tokenizeText(text, { resolver }),
      scope,
    });

    // One file, two lines, two different bundled detections.
    const mixedFile = (name: string): { file: string; monitoredLine: string } => {
      const secretLine = `{"text":"key ${SECRET} end"}`;
      const monitoredLine = `{"text":"contact ${MONITORED} end"}`;
      return {
        file: transcriptFile(name, `${secretLine}\n${monitoredLine}\n`),
        monitoredLine,
      };
    };

    it('leaves a Monitor detection where it is while a Redact & Vault one in the same file becomes a pointer', async () => {
      const { file, monitoredLine } = mixedFile('mixed.jsonl');
      const resolver = createPolicyResolver(
        bundleWith({ [AWS_RULE]: 'redact', [MONITORED_RULE]: 'log' }, [AWS_RULE]),
      );

      expect(await scrubTranscriptTail(file, depsWith(resolver))).toEqual({ rewritten: 1 });

      const [enforced, monitored] = readFileSync(file, 'utf8').split('\n');
      // The enforced line is the positive control: it moved, in this file and
      // this run, so the untouched line below is a policy decision rather than
      // a scrub that did nothing at all.
      expect(pointersIn(enforced ?? '')).toHaveLength(1);
      expectNoEchoOf(enforced, SECRET);
      // Byte-identical, value included — Monitor logged it and touched nothing.
      expect(monitored).toBe(monitoredLine);
      expect(monitored).toContain(MONITORED);
    });

    // Non-vacuity control for the case above, and the reported defect itself:
    // the monitored rule DOES fire on that line, and with nothing to narrow the
    // self-scan its value is lifted into the vault exactly like the secret's.
    it('rewrites and vaults BOTH values when no resolver narrows the self-scan', async () => {
      const { file } = mixedFile('unpoliced.jsonl');

      expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 2 });

      const [enforced, monitored] = readFileSync(file, 'utf8').split('\n');
      expect(pointersIn(enforced ?? '')).toHaveLength(1);
      expect(pointersIn(monitored ?? '')).toHaveLength(1);
      expectNoEchoOf(monitored, MONITORED);
    });

    // A Redact (non-vault) span mints no pointer and degrades nothing, so the
    // two-count blanket test read this correct rewrite as unclassifiable and
    // abandoned the whole file.
    it('strikes a Redact detection one-way without tripping the blanket abort', async () => {
      const { file, monitoredLine } = mixedFile('one-way.jsonl');
      const resolver = createPolicyResolver(
        bundleWith({ [AWS_RULE]: 'redact', [MONITORED_RULE]: 'log' }, []),
      );

      expect(await scrubTranscriptTail(file, depsWith(resolver))).toEqual({ rewritten: 1 });

      const [enforced, monitored] = readFileSync(file, 'utf8').split('\n');
      expect(enforced).toContain('[REDACTED:SECRET]');
      expect(pointersIn(enforced ?? '')).toHaveLength(0);
      expectNoEchoOf(enforced, SECRET);
      expect(monitored).toBe(monitoredLine);
    });
  });
});
