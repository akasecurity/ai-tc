import type { FindingUser } from '@akasecurity/schema';

/** User cell for one instance — the attributed person's label, or a neutral
 * dash where the store attributes findings to no one. Shared by the grouped
 * and flat findings tables so both render a person the same way. */
export function UserCell({ user }: { user: FindingUser | undefined }) {
  if (!user) return <span className="text-text-3">—</span>;
  return (
    <span className="text-xs text-text-2 wrap-anywhere" title={user.name}>
      {user.name}
    </span>
  );
}

/** User cell for a group row — the one attributed person's label when there is
 * exactly one, a count when there are several, or a neutral dash when none. */
export function UsersCell({ users }: { users: FindingUser[] | undefined }) {
  const first = users?.[0];
  if (!first) return <span className="text-text-3">—</span>;
  if (users.length === 1) return <UserCell user={first} />;
  return <span className="text-xs text-text-2">{users.length} users</span>;
}
