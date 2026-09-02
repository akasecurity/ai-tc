import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { UserCell, UsersCell } from '../../src/findings/UserCell.tsx';

const alice = { id: 'u-alice', name: 'alice@example.com' };
const bob = { id: 'u-bob', name: 'bob@example.com' };

describe('UserCell', () => {
  it('renders the label, with the full label as the hover title', () => {
    const html = renderToStaticMarkup(<UserCell user={alice} />);
    expect(html).toContain('alice@example.com');
    expect(html).toContain('title="alice@example.com"');
  });

  it('renders a neutral dash for no user', () => {
    expect(renderToStaticMarkup(<UserCell user={undefined} />)).toBe(
      '<span class="text-text-3">—</span>',
    );
  });
});

describe('UsersCell', () => {
  it('renders the one person exactly as UserCell does', () => {
    expect(renderToStaticMarkup(<UsersCell users={[alice]} />)).toBe(
      renderToStaticMarkup(<UserCell user={alice} />),
    );
  });

  it('renders a count for several, naming nobody', () => {
    const html = renderToStaticMarkup(<UsersCell users={[alice, bob]} />);
    expect(html).toContain('2 users');
    expect(html).not.toContain('alice');
    expect(html).not.toContain('bob');
  });

  it('renders a neutral dash for none, absent or empty', () => {
    const dash = '<span class="text-text-3">—</span>';
    expect(renderToStaticMarkup(<UsersCell users={undefined} />)).toBe(dash);
    expect(renderToStaticMarkup(<UsersCell users={[]} />)).toBe(dash);
  });
});
