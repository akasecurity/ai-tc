// A model mark: a small square tile identifying a model's family. It renders a
// lettermark on one of the ui-kit tonal pairs, so both its fill and its letter
// are theme tokens and re-theme with the page. The tone set is the categorical
// families only (teal, violet, primary, neutral) — never a severity tone, so a
// mark cannot read as a finding's severity.
//
// Resolution order: the catalog `familyId`, then the catalog `vendor`, then the
// first letter of `label` on the neutral tone.
import type { ModelVendor } from '@akasecurity/schema';
import { cn, type Tone, TONE_SOFT } from '@akasecurity/ui-kit';

/** What a model mark draws: one letter on one tonal pair. */
export interface ModelMarkGlyph {
  letter: string;
  tone: Extract<Tone, 'teal' | 'violet' | 'primary' | 'neutral'>;
}

/** Known model families, keyed by catalog family id. */
export const MODEL_FAMILY_MARKS: Readonly<Record<string, ModelMarkGlyph>> = {
  claude: { letter: 'C', tone: 'violet' },
  gpt: { letter: 'O', tone: 'teal' },
  gemini: { letter: 'G', tone: 'primary' },
  llama: { letter: 'L', tone: 'primary' },
  mistral: { letter: 'M', tone: 'violet' },
  deepseek: { letter: 'D', tone: 'primary' },
  qwen: { letter: 'Q', tone: 'violet' },
  grok: { letter: 'X', tone: 'neutral' },
  command: { letter: 'C', tone: 'teal' },
  nova: { letter: 'N', tone: 'neutral' },
};

/** The family each catalog vendor's mark is drawn from; `null` has none. */
const VENDOR_FAMILY = {
  anthropic: 'claude',
  openai: 'gpt',
  google: 'gemini',
  meta: 'llama',
  mistral: 'mistral',
  deepseek: 'deepseek',
  alibaba: 'qwen',
  xai: 'grok',
  amazon: 'nova',
  cohere: 'command',
  unknown: null,
} satisfies Record<ModelVendor, string | null>;

function isModelVendor(vendor: string): vendor is ModelVendor {
  return Object.hasOwn(VENDOR_FAMILY, vendor);
}

function knownFamily(familyId: string | undefined): ModelMarkGlyph | undefined {
  if (familyId === undefined || !Object.hasOwn(MODEL_FAMILY_MARKS, familyId)) return undefined;
  return MODEL_FAMILY_MARKS[familyId];
}

/**
 * The glyph a mark draws for a model. A known family wins, then a known vendor;
 * anything else is the first letter or digit of `label` on the neutral tone, or
 * `?` when the label has none.
 */
export function modelMarkFor(input: {
  familyId?: string | undefined;
  vendor?: string | undefined;
  label: string;
}): ModelMarkGlyph {
  const byFamily = knownFamily(input.familyId);
  if (byFamily !== undefined) return byFamily;

  if (input.vendor !== undefined && isModelVendor(input.vendor)) {
    const byVendor = knownFamily(VENDOR_FAMILY[input.vendor] ?? undefined);
    if (byVendor !== undefined) return byVendor;
  }

  const first = /[\p{L}\p{N}]/u.exec(input.label)?.[0];
  return { letter: first === undefined ? '?' : first.toUpperCase(), tone: 'neutral' };
}

const SIZE_CLASS = {
  sm: 'size-5 rounded-md text-[10px]',
  md: 'size-7 rounded-lg text-xs',
} as const;

export interface ModelMarkProps {
  /** The catalog family id (`claude`, `gpt`, …). */
  familyId?: string | undefined;
  /** The catalog vendor (`anthropic`, `openai`, …), used when the family is not known. */
  vendor?: string | undefined;
  /** The model's name. It is the mark's accessible name, and its fallback letter. */
  label: string;
  size?: keyof typeof SIZE_CLASS;
  /**
   * Set when the model's name is already rendered next to the mark. The tile is
   * then hidden from assistive technology, so the name is not announced twice.
   */
  decorative?: boolean;
  className?: string;
}

/**
 * A lettermark tile for a model family.
 *
 * Accessibility: the letter itself is always `aria-hidden`. By default the tile
 * is `role="img"` with `label` as its accessible name, so a screen reader
 * announces the model, not the letter. With `decorative`, the whole tile is
 * hidden and the caller's adjacent text carries the name.
 */
export function ModelMark({
  familyId,
  vendor,
  label,
  size = 'md',
  decorative = false,
  className,
}: ModelMarkProps) {
  const glyph = modelMarkFor({ familyId, vendor, label });
  const a11y = decorative
    ? ({ 'aria-hidden': true } as const)
    : ({ role: 'img', 'aria-label': label } as const);
  return (
    <span
      data-slot="model-mark"
      data-tone={glyph.tone}
      className={cn(
        'inline-flex shrink-0 items-center justify-center font-display font-semibold',
        SIZE_CLASS[size],
        TONE_SOFT[glyph.tone],
        className,
      )}
      {...a11y}
    >
      <span aria-hidden="true">{glyph.letter}</span>
    </span>
  );
}
