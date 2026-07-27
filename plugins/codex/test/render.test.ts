import { severityFloorPosture } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  RE_TUNE_HINT,
  renderAdjustConfirm,
  renderApplied,
  renderCategoriesTuned,
  renderPosture,
  renderPostureGrid,
  renderRecommendedPosture,
  renderStartLight,
} from '../src/render.ts';
import { readRegisteredSkills } from '../src/skills-registry.ts';

describe('renderPosture', () => {
  it('lists each category with its action, aligned', () => {
    const out = renderPosture([
      { category: 'secret', action: 'warn' },
      { category: 'code_context', action: 'log' },
    ]);
    expect(out).toContain('secret');
    expect(out).toContain('warn');
    expect(out).toContain('code_context');
    // 'log' (ActionTaken) surfaces to the user as 'monitor'
    expect(out).toContain('monitor');
    expect(out).not.toMatch(/\blog\b/);
  });

  it('orders rows canonically regardless of input order', () => {
    // Rows arrive in whatever order the store returned them; the card must
    // render in the schema's canonical category order so it stays stable.
    const out = renderPosture([
      { category: 'code_context', action: 'monitor' },
      { category: 'secret', action: 'warn' },
      { category: 'pii', action: 'warn' },
      { category: 'financial', action: 'monitor' },
    ]);
    const order = out.split('\n').map((line) => line.trim().split(/\s+/)[0]);
    expect(order).toEqual(['pii', 'financial', 'secret', 'code_context']);
  });
});

describe('renderRecommendedPosture — condensed recommended view', () => {
  it('shows each pack with its recommended level, compact and in canonical order', () => {
    const out = renderRecommendedPosture(severityFloorPosture());
    // One compact row per pack — the recommended level, not the full 8×4 grid of
    // every level (that is the start-light branch's table).
    const packs = out
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => line.trim().split(/\s+/)[0]);
    expect(packs).toEqual([
      'pii',
      'financial',
      'secret',
      'phi',
      'code_context',
      'code_flaw',
      'custom',
      'config',
    ]);
    // The recommendation: sensitive packs surface (warn); observe-only packs
    // monitor. Palette vocabulary only — no DB 'log' leaks through.
    expect(out).not.toMatch(/\blog\b/);
    expect(out).not.toMatch(/\bblock\b/);
    // The whole block, so a layout/copy regression is caught as a snapshot diff.
    expect(out).toMatchInlineSnapshot(`
      "  pii           warn
        financial     warn
        secret        warn
        phi           warn
        code_context  monitor
        code_flaw     warn
        custom        warn
        config        monitor"
    `);
  });

  it('renders whatever recommended map it is handed (no hardcoded levels)', () => {
    const out = renderRecommendedPosture({
      secret: 'block',
      pii: 'redact',
      financial: 'warn',
      phi: 'warn',
      code_context: 'monitor',
      code_flaw: 'warn',
      custom: 'warn',
      config: 'monitor',
    });
    expect(out).toContain('secret');
    expect(out).toContain('block');
    expect(out).toContain('redact');
  });
});

describe('renderPostureGrid — full 8×4 posture matrix', () => {
  // The eight packs, in the schema's canonical category order — the same order
  // renderPosture/renderRecommendedPosture use, and the order the grid must lock.
  const CANONICAL = [
    'pii',
    'financial',
    'secret',
    'phi',
    'code_context',
    'code_flaw',
    'custom',
    'config',
  ];

  it('lays every pack against all four levels, marks the chosen one, in canonical order', () => {
    const out = renderPostureGrid(severityFloorPosture());

    // Every pack renders, once, in canonical category order (header and rule
    // lines excluded by keeping only rows whose first token is a known pack).
    const packs = out
      .split('\n')
      .map((line) => line.trim().split(/\s+/)[0])
      .filter((tok): tok is string => tok !== undefined && CANONICAL.includes(tok));
    expect(packs).toEqual(CANONICAL);

    // All four level labels head the grid — palette vocabulary only, never the
    // DB action forms 'log'/'allow' (the full grid lays out every level per pack,
    // unlike renderRecommendedPosture's condensed one-level glance).
    expect(out).toContain('MONITOR');
    expect(out).toContain('WARN');
    expect(out).toContain('REDACT');
    expect(out).toContain('BLOCK');
    expect(out).not.toMatch(/\blog\b/);
    expect(out).not.toMatch(/\ballow\b/);

    // The whole 8×4 grid, so a layout regression is caught as a snapshot diff.
    // Feeding the default posture map, the mark sits in monitor for the observe-only
    // packs (code_context, config) and in warn for the rest.
    expect(out).toMatchInlineSnapshot(`
      "  CATEGORY       MONITOR   WARN   REDACT   BLOCK
        ────────────   ───────   ────   ──────   ─────
        pii                      ●                    
        financial                ●                    
        secret                   ●                    
        phi                      ●                    
        code_context   ●                              
        code_flaw                ●                    
        custom                   ●                    
        config         ●                              "
    `);
  });
});

describe('renderStartLight — start-light card', () => {
  // The eight packs in canonical category order — the order the embedded grid and
  // the per-pack rationale block must both follow.
  const CANONICAL = [
    'pii',
    'financial',
    'secret',
    'phi',
    'code_context',
    'code_flaw',
    'custom',
    'config',
  ];
  const posture = severityFloorPosture();

  it('leads with the start-light heading', () => {
    expect(renderStartLight(posture)).toContain('Starting light — your detection categories');
  });

  it('embeds the full 8×4 default posture grid, composed from the shared primitive', () => {
    // The card composes renderPostureGrid seeded with the default posture, so a grid
    // layout regression surfaces here too, not only in renderPostureGrid's own test.
    expect(renderStartLight(posture)).toContain(renderPostureGrid(posture));
  });

  it('carries a per-pack rationale line for every pack, never omitted or placeholdered', () => {
    const out = renderStartLight(posture);
    for (const pack of CANONICAL) {
      // A rationale line names the pack, its default level, then a non-empty reason.
      const line = out.split('\n').find((l) => l.trim().startsWith(`${pack} —`));
      expect(line, `rationale line for ${pack}`).toBeTruthy();
      const reason = (line ?? '').split(':').slice(1).join(':').trim();
      expect(reason.length, `rationale text for ${pack}`).toBeGreaterThan(0);
      expect(reason, `rationale for ${pack} is not a placeholder`).not.toMatch(
        /todo|tbd|placeholder|…|xxx/i,
      );
    }
  });

  it('closes with the re-tune hint, single-sourced from RE_TUNE_HINT', () => {
    // The exported constant is what the setup skill's prose and the applied-frame
    // copy single-source.
    expect(RE_TUNE_HINT).toBe('Re-tune anytime with the aka-setup skill or the dashboard');
    expect(renderStartLight(posture)).toContain(RE_TUNE_HINT);
  });

  it('matches the whole-card snapshot so copy/layout regressions surface', () => {
    expect(renderStartLight(posture)).toMatchInlineSnapshot(`
      "● Starting light — your detection categories

        For now, each detection category starts at a careful default. Run the aka-setup skill whenever you like and I'll tune these from Codex's recent work.

        CATEGORY       MONITOR   WARN   REDACT   BLOCK
        ────────────   ───────   ────   ──────   ─────
        pii                      ●                    
        financial                ●                    
        secret                   ●                    
        phi                      ●                    
        code_context   ●                              
        code_flaw                ●                    
        custom                   ●                    
        config         ●                              

        pii — warn: personal data carries real obligations, so I surface it before it moves.
        financial — warn: card and account numbers are sensitive by default, so these come to you.
        secret — warn: keys and credentials are the costliest thing to lose, so I bring those straight to you.
        phi — warn: health information is regulated wherever it lands, so I flag it for your call.
        code_context — monitor: proprietary code context is common and mostly benign, so I watch quietly and keep the record.
        code_flaw — warn: an insecure pattern is worth a look before it ships, so I raise it.
        custom — warn: your own policy matches start surfaced so nothing you care about slips by unseen.
        config — monitor: config values are noisy, so I keep an eye on them without notifying you.

        Re-tune anytime with the aka-setup skill or the dashboard"
    `);
  });
});

describe('renderAdjustConfirm — adjust-confirm table', () => {
  // The eight packs in canonical category order — the order the confirm table
  // rows must follow, recommended and yours side by side on each.
  const CANONICAL = [
    'pii',
    'financial',
    'secret',
    'phi',
    'code_context',
    'code_flaw',
    'custom',
    'config',
  ];
  const recommended = severityFloorPosture();
  // The user's chosen posture: the recommended base with two packs overridden
  // (secret warn→redact, config monitor→warn), the other six kept as recommended.
  const chosen: Partial<Record<DetectionCategory, BuiltinPolicyId>> = {
    ...recommended,
    secret: 'redact',
    config: 'warn',
  };

  it("heads a three-column 'category │ recommended │ yours' table", () => {
    // Built from present.ts table(), which uppercases the column headers.
    const out = renderAdjustConfirm(recommended, chosen);
    expect(out).toContain('CATEGORY');
    expect(out).toContain('RECOMMENDED');
    expect(out).toContain('YOURS');
  });

  it('lays one row per pack in canonical order, recommended beside yours', () => {
    const out = renderAdjustConfirm(recommended, chosen);
    const order = out
      .split('\n')
      .map((l) => l.trim().split(/\s+/)[0])
      .filter((tok): tok is string => tok !== undefined && CANONICAL.includes(tok));
    expect(order).toEqual(CANONICAL);

    // Both columns are visible on every row: a changed pack shows a different
    // 'yours' value, an unchanged pack repeats the recommended level.
    const row = (pack: string): string[] =>
      (out.split('\n').find((l) => l.trim().startsWith(`${pack} `)) ?? '').trim().split(/\s+/);
    // secret: recommended warn, yours redact (changed).
    expect(row('secret')).toEqual(['secret', 'warn', 'redact']);
    // config: recommended monitor, yours warn (changed).
    expect(row('config')).toEqual(['config', 'monitor', 'warn']);
    // pii: unchanged — recommended and yours both warn, both columns present.
    expect(row('pii')).toEqual(['pii', 'warn', 'warn']);
  });

  // The adjust fork writes posture just like the confirm spine, so it must flag an
  // enforcement downgrade the same way — a pack hardened out of band can otherwise
  // be lowered here with nothing shown to the user.
  describe('downgrade guard against the stored posture', () => {
    it('appends the downgrade footer when a pick ranks below the stored action', () => {
      // The store holds 'secret' at block; the user picks redact.
      const out = renderAdjustConfirm(recommended, chosen, { secret: 'block' });
      expect(out).toContain('Heads up — this would lower 1 detection level (secret) below');
    });

    it('names every lowered detection category and pluralizes the count', () => {
      const out = renderAdjustConfirm(recommended, chosen, {
        secret: 'block',
        config: 'redact',
      });
      expect(out).toContain('Heads up — this would lower 2 detection levels (secret, config) below');
    });

    it('stays silent when every pick is the same or stronger than the stored action', () => {
      // secret: stored warn -> picked redact (stronger). config: stored log
      // ('monitor') -> picked warn (stronger).
      const out = renderAdjustConfirm(recommended, chosen, { secret: 'warn', config: 'log' });
      expect(out).not.toContain('WARNING');
    });

    it('has no baseline to compare against when current is omitted', () => {
      expect(renderAdjustConfirm(recommended, chosen)).not.toContain('WARNING');
    });
  });

  it('carries the adjust copy and the shared re-tune hint', () => {
    const out = renderAdjustConfirm(recommended, chosen);
    expect(out).toContain("I'll keep the rest as recommended");
    // The re-tune pointer to the deep-tuning surface is single-sourced.
    expect(out).toContain(RE_TUNE_HINT);
  });

  it('matches the whole-card snapshot so copy/layout regressions surface', () => {
    expect(renderAdjustConfirm(recommended, chosen)).toMatchInlineSnapshot(`
      "● Adjust — set the detection categories you want, keep the rest

        CATEGORY       RECOMMENDED   YOURS  
        ────────────   ───────────   ───────
        pii            warn          warn   
        financial      warn          warn   
        secret         warn          redact 
        phi            warn          warn   
        code_context   monitor       monitor
        code_flaw      warn          warn   
        custom         warn          warn   
        config         monitor       warn   

        I'll keep the rest as recommended.

        Re-tune anytime with the aka-setup skill or the dashboard"
    `);
  });
});

describe('renderApplied — applying confirmation', () => {
  // The installed skill registry, resolved the way the shipped caller does and
  // threaded into the pure renderer so the Ready line's curated set is validated
  // against the skills the plugin actually registers.
  const REGISTRY = readRegisteredSkills();
  const REGISTERED = new Set(REGISTRY);

  it('templates the real dismissed count and confirms the tuned category count', () => {
    const out = renderApplied(8, 12, REGISTRY);
    expect(out).toContain('✓ Set all 8 detection categories');
    expect(out).toContain('set aside 12 routine results');
    // N is templated from the real count — a different value flows straight
    // through, never a baked-in literal.
    expect(renderApplied(8, 3, REGISTRY)).toContain('set aside 3 routine results');
    // Singular is grammatical when exactly one routine result was set aside.
    expect(renderApplied(8, 1, REGISTRY)).toContain('set aside 1 routine result');
    expect(renderApplied(8, 1, REGISTRY)).not.toContain('1 routine results');
    // The tuned count is threaded too, not hardcoded to 8.
    expect(renderApplied(5, 3, REGISTRY)).toContain('✓ Set all 5 detection categories');
  });

  it('renders an honest empty-state when nothing routine was set aside', () => {
    const out = renderApplied(8, 0, REGISTRY);
    expect(out).toContain('✓ Set all 8 detection categories');
    // No fabricated 'set aside 0 routine results' — honest copy instead.
    expect(out).not.toContain('set aside 0');
    expect(out).toContain('nothing routine to set aside');
  });

  it('the Ready line names only skills the plugin actually registers, by their declared names', () => {
    const ready = (renderApplied(8, 5, REGISTRY).split('Ready:')[1] ?? '').trim();
    const named = ready.match(/aka-[a-z]+/g) ?? [];
    // The line actually names skills (guards against an empty match passing).
    expect(named.length).toBeGreaterThan(0);
    for (const skill of named) {
      // The plugin registers each skill under the name its SKILL.md frontmatter
      // declares — the form the user invokes it by. The named skill must be a
      // real registered one (never a hardcoded copy).
      expect(REGISTERED.has(skill)).toBe(true);
    }
  });

  it('builds the Ready line through the registry mechanism — an unregistered curated skill throws', () => {
    // The Ready line's curated set is validated against the registry, not
    // free-printed: a registry missing one of its curated skills fails loud
    // rather than rendering a call-to-action the user cannot invoke.
    const withoutHealth = REGISTRY.filter((s) => s !== 'aka-health');
    expect(() => renderApplied(8, 5, withoutHealth)).toThrow(/aka-health/);
  });

  it("reads '✓ Set all 8 detection categories' from the real 8-pack the posture writer wrote", () => {
    // onboard.ts feeds its confirmation the size of the posture it actually
    // wrote: renderCategoriesTuned(Object.keys(posture).length). Drive that with
    // the real recommended map so the '8' is the true pack count, not a
    // literal — this is the segment that composes into the applying-confirmation line.
    const packCount = Object.keys(severityFloorPosture()).length;
    expect(packCount).toBe(8);
    expect(renderCategoriesTuned(packCount)).toBe('✓ Set all 8 detection categories');
    // Same phrase renderApplied composes — single-sourced, so the two can't drift.
    expect(renderApplied(packCount, 5, REGISTRY)).toContain(renderCategoriesTuned(packCount));
  });
});
