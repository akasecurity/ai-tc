import type { FindingUser } from '@akasecurity/schema';
import type { ReactNode } from 'react';

/**
 * Renders an attributed person in place of the plain label. The returned node
 * is placed inside the cell's own span, which supplies the typography, the
 * wrapping and the full label as its tooltip. It is not called for a row with
 * no user, nor for a group row naming several people.
 *
 * The node sits inside a table row that opens the finding on click. A link or
 * button in it must stop the click's propagation, or the finding opens as
 * well. Pass it from a client component: a function cannot cross into a
 * client component from a server one.
 */
export type RenderFindingUser = (user: FindingUser) => ReactNode;

/** User cell for one instance — the attributed person's label, or a neutral
 * dash where the store attributes findings to no one. Shared by the grouped
 * and flat findings tables so both render a person the same way. */
export function UserCell({
  user,
  render,
}: {
  user: FindingUser | undefined;
  render?: RenderFindingUser | undefined;
}) {
  if (!user) return <span className="text-text-3">—</span>;
  if (render) {
    return (
      <span className="text-xs text-text-2 wrap-anywhere" title={user.name}>
        {render(user)}
      </span>
    );
  }
  return (
    <span className="text-xs text-text-2 wrap-anywhere" title={user.name}>
      {user.name}
    </span>
  );
}

/** User cell for a group row — the one attributed person's label when there is
 * exactly one, a count when there are several, or a neutral dash when none.
 * `render` applies to the one-person row only. */
export function UsersCell({
  users,
  render,
}: {
  users: FindingUser[] | undefined;
  render?: RenderFindingUser | undefined;
}) {
  const first = users?.[0];
  if (!first) return <span className="text-text-3">—</span>;
  if (users.length === 1) return <UserCell user={first} render={render} />;
  return <span className="text-xs text-text-2">{users.length} users</span>;
}
