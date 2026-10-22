import type { CredentialListItem } from './types.ts';

type Named = Pick<CredentialListItem, 'label' | 'variableName' | 'displayName' | 'kind'>;

/** The label, or null when there is none or it is blank. */
export function credentialLabel(item: Pick<CredentialListItem, 'label'>): string | null {
  return item.label !== null && item.label.trim() !== '' ? item.label : null;
}

/**
 * The name a view shows for a credential, and whether it is the variable name,
 * which renders as code. A blank `displayName` falls back to the label, the
 * variable name, then the kind, so a heading is never empty.
 */
export function credentialName(item: Named): { text: string; isVariable: boolean } {
  const label = credentialLabel(item);
  const text =
    item.displayName.trim() !== '' ? item.displayName : (label ?? item.variableName ?? item.kind);
  return { text, isVariable: label === null && text === item.variableName };
}
