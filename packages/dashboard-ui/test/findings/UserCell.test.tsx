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

  it('renders the host node in place of the label, inside the cell wrapping span', () => {
    const html = renderToStaticMarkup(<UserCell user={alice} render={() => <b>host</b>} />);
    expect(html).toBe('<span class="text-xs text-text-2 wrap-anywhere"><b>host</b></span>');
    expect(html).not.toContain(alice.name);
  });

  it('hands the host the attributed user', () => {
    const html = renderToStaticMarkup(<UserCell user={alice} render={(u) => <b>{u.id}</b>} />);
    expect(html).toContain('<b>u-alice</b>');
  });

  it('renders the plain label unchanged when render is undefined', () => {
    expect(renderToStaticMarkup(<UserCell user={alice} render={undefined} />)).toBe(
      renderToStaticMarkup(<UserCell user={alice} />),
    );
  });

  it('never calls render for a row with no user', () => {
    let calls = 0;
    const html = renderToStaticMarkup(
      <UserCell
        user={undefined}
        render={() => {
          calls += 1;
          return null;
        }}
      />,
    );
    expect(html).toBe('<span class="text-text-3">—</span>');
    expect(calls).toBe(0);
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

  it('routes the one-person row through render, and not the count row', () => {
    const host = () => <b>host</b>;
    expect(renderToStaticMarkup(<UsersCell users={[alice]} render={host} />)).toContain(
      '<b>host</b>',
    );
    const several = renderToStaticMarkup(<UsersCell users={[alice, bob]} render={host} />);
    expect(several).toContain('2 users');
    expect(several).not.toContain('<b>host</b>');
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
