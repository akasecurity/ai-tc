import { randomUUID } from 'node:crypto';
import {
  appendFileSync,
  chmodSync,
  existsSync,
  lstatSync,
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

  it('publishes a group-writable transcript at its exact mode', async (ctx) => {
    if (process.platform === 'win32') ctx.skip('POSIX permission bits');
    // 0660 carries bits the usual 0022 umask CLEARS on create, so the write's
    // `mode` option alone narrows it to 0640 — re-applying the bits rather
    // than preserving them. The chmod after the exclusive create is what
    // makes it exact. The probe measures what this process's umask would have
    // left behind, so a umask that narrows nothing in 0660 says so instead of
    // passing blind.
    const probe = join(transcriptRoot, 'umask-probe');
    writeFileSync(probe, '', { mode: 0o660 });
    if ((statSync(probe).mode & 0o777) === 0o660) {
      ctx.skip('this process umask narrows nothing in 0660');
    }

    const file = transcriptFile('exact-mode.jsonl', `{"text":"key ${SECRET}"}\n`);
    chmodSync(file, 0o660);

    expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 1 });

    expect(statSync(file).mode & 0o777).toBe(0o660);
  });

  describe('.aka-scrub.tmp cleanup', () => {
    // A pid no platform can hand out: Linux caps `pid_max` at 2^22 and macOS at
    // 99999, so `kill(pid, 0)` answers ESRCH here rather than racing some real
    // process. That makes "a killed earlier run" a fixture rather than a gamble
    // on pid reuse.
    const DEAD_PID = 1_073_741_823;

    // The temp path this module mints for `transcript` when it runs as `pid`.
    const tempName = (transcript: string, pid: number): string =>
      `${transcript}.${String(pid)}.aka-scrub.tmp`;

    // Entries left behind matching the atomic-write sibling-temp-file naming.
    const orphanedTmpEntries = (): string[] =>
      readdirSync(join(transcriptRoot, '-Users-me-project'))
        .filter((entry) => entry.endsWith('.aka-scrub.tmp'))
        .sort();

    it('clears a leftover carrying its own pid rather than writing through it', async (ctx) => {
      if (process.platform === 'win32') ctx.skip('POSIX permission bits');
      const file = transcriptFile('leftover.jsonl', `{"text":"key ${SECRET}"}\n`);
      chmodSync(file, 0o600);
      // The one temp path this process would pick, left behind by an earlier
      // process that happened to carry the same pid. Writing through it would
      // publish the transcript with the leftover's permission bits, since a
      // write applies its mode only when it CREATES the file.
      writeFileSync(tempName(file, process.pid), 'stale', { mode: 0o644 });

      expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 1 });

      expect(statSync(file).mode & 0o777).toBe(0o600);
      const after = readFileSync(file, 'utf8');
      expect(after).toContain('[[aka:');
      expectNoEchoOf(after, SECRET);
      expect(orphanedTmpEntries()).toEqual([]);
    });

    it('sweeps the copy a killed earlier run stranded beside the transcript', async () => {
      const file = transcriptFile('stranded.jsonl', `{"text":"key ${SECRET}"}\n`);
      // A temp a run that died between the write and the rename left behind: a
      // whole copy of the transcript that nothing else would ever remove.
      const stranded = tempName(file, DEAD_PID);
      writeFileSync(stranded, `{"text":"stranded copy ${SECRET}"}\n`);

      expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 1 });

      expect(existsSync(stranded)).toBe(false);
      expect(orphanedTmpEntries()).toEqual([]);
    });

    it('sweeps the pid-free copy an older build stranded', async () => {
      const file = transcriptFile('legacy.jsonl', `{"text":"key ${SECRET}"}\n`);
      // The name this module wrote before the pid went into it. No pid means no
      // owner to ask about, so it is swept unconditionally — otherwise the one
      // leftover shape already sitting on real disks is the one shape the sweep
      // cannot see, and a whole plaintext copy stays there for good.
      const legacy = `${file}.aka-scrub.tmp`;
      writeFileSync(legacy, `{"text":"stranded copy ${SECRET}"}\n`);

      expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 1 });

      expect(existsSync(legacy)).toBe(false);
      expect(orphanedTmpEntries()).toEqual([]);
    });

    it('sweeps a stranded copy even when this pass rewrites nothing', async () => {
      const content = '{"text":"all clear"}\n';
      const file = transcriptFile('clean.jsonl', content);
      const stranded = tempName(file, DEAD_PID);
      writeFileSync(stranded, `{"text":"stranded copy ${SECRET}"}\n`);

      // The transcript stays byte-identical — the sweep runs on every transcript
      // the pass opens, not only on the ones it goes on to rewrite.
      expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 0 });
      expect(readFileSync(file, 'utf8')).toBe(content);
      expect(existsSync(stranded)).toBe(false);
    });

    it('sweeps a stranded copy even when the transcript is too large to scrub', async () => {
      const content = `{"text":"key ${SECRET}"}\n`;
      const file = transcriptFile('oversized.jsonl', content);
      const stranded = tempName(file, DEAD_PID);
      writeFileSync(stranded, `{"text":"stranded copy ${SECRET}"}\n`);

      // A transcript over the cap is skipped whole, and it only ever grows — so
      // a sweep that ran after the size gate would never reach this copy again.
      expect(await scrubTranscriptTail(file, { ...deps, maxBytes: 8 })).toBeNull();
      expect(readFileSync(file, 'utf8')).toBe(content);
      expect(existsSync(stranded)).toBe(false);
    });

    it("leaves a live run's temp file alone", async () => {
      const file = transcriptFile('live.jsonl', `{"text":"key ${SECRET}"}\n`);
      // The parent of this test process is alive by construction, so its temp is
      // work in progress rather than a leftover — sweeping it would delete
      // another run's bytes out from under its own rename.
      const live = tempName(file, process.ppid);
      writeFileSync(live, 'in flight');

      await scrubTranscriptTail(file, deps);

      expect(readFileSync(live, 'utf8')).toBe('in flight');
    });

    it('never removes a sibling it did not name', async () => {
      const file = transcriptFile('bystanders.jsonl', `{"text":"key ${SECRET}"}\n`);
      const bystanders = [
        `${file}.notapid.aka-scrub.tmp`,
        `${file}. 7.aka-scrub.tmp`,
        // A temp belonging to a DIFFERENT transcript in the same directory.
        tempName(join(transcriptRoot, '-Users-me-project', 'other.jsonl'), DEAD_PID),
        // The suffix has to end the name, not merely appear in it.
        `${tempName(file, DEAD_PID)}.bak`,
      ];
      for (const path of bystanders) writeFileSync(path, 'not ours');

      await scrubTranscriptTail(file, deps);

      for (const path of bystanders) expect(existsSync(path)).toBe(true);
    });

    it('refuses to publish through a symlink planted at its temp path', async (ctx) => {
      if (process.platform === 'win32') {
        ctx.skip('unprivileged symlink creation is not available on Windows');
      }
      const content = `{"text":"key ${SECRET}"}\n`;
      const file = transcriptFile('planted.jsonl', content);
      // A file outside every artifact root, standing in for whatever a planted
      // link would aim at. Following the link would copy this transcript's whole
      // contents over it and then rename the link itself over the transcript.
      const outside = join(outsideRoot, 'notes.txt');
      writeFileSync(outside, 'untouched');
      symlinkSync(outside, tempName(file, process.pid));

      // Doubt at the temp path comes out as "did nothing": no write, no rewrite.
      expect(await scrubTranscriptTail(file, deps)).toBeNull();
      expect(readFileSync(outside, 'utf8')).toBe('untouched');
      expect(readFileSync(file, 'utf8')).toBe(content);
      expect(lstatSync(file).isSymbolicLink()).toBe(false);
      expect(orphanedTmpEntries()).toEqual([]);
    });
  });

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
