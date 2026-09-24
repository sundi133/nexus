"use client";

import { useQuery } from "@tanstack/react-query";
import { Command } from "cmdk";
import { Dialog as D } from "radix-ui";
import { LogOut, Search, User as UserIcon, UsersRound } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Avatar, Kbd } from "@/components/ui/misc";
import { api, bffAuth, unwrap } from "@/lib/api";
import { NAV } from "./nav";

/** ⌘K: navigate, find any user or group, and run actions (docs/UI.md §4.3). */
export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const router = useRouter();
  const [q, setQ] = useState("");
  const search = q.trim();

  const users = useQuery({
    queryKey: ["palette-users", search],
    queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { q: search, limit: 6 } } })),
    enabled: open && search.length > 1,
  });
  const groups = useQuery({
    queryKey: ["palette-groups", search],
    queryFn: () => unwrap(api.GET("/v1/groups", { params: { query: { q: search, limit: 4 } } })),
    enabled: open && search.length > 1,
  });

  useEffect(() => {
    if (!open) setQ("");
  }, [open]);

  const go = (href: string) => {
    onOpenChange(false);
    router.push(href);
  };

  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-50 bg-black/40" />
        <D.Content className="fixed left-1/2 top-[14vh] z-50 w-[calc(100vw-32px)] max-w-xl -translate-x-1/2 overflow-hidden rounded-lg border border-border bg-bg shadow-2xl">
          <D.Title className="sr-only">Command palette</D.Title>
          <D.Description className="sr-only">Search users and groups, or jump to a page</D.Description>
          <Command shouldFilter={false} label="Command palette" className="[&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-fg-subtle">
            <div className="flex items-center gap-2 border-b border-border px-3">
              <Search className="size-4 text-fg-subtle" />
              <Command.Input
                value={q}
                onValueChange={setQ}
                placeholder="Search users, groups, pages…"
                className="h-12 flex-1 bg-transparent text-sm outline-none placeholder:text-fg-subtle"
              />
              <Kbd>esc</Kbd>
            </div>
            <Command.List className="max-h-[60vh] overflow-y-auto p-1.5">
              <Command.Empty className="px-3 py-6 text-center text-[13px] text-fg-muted">No results</Command.Empty>
              {users.data?.data.length ? (
                <Command.Group heading="Users">
                  {users.data.data.map((u) => (
                    <Item key={u.id} onSelect={() => go(`/users/${u.id}`)}>
                      <Avatar name={u.display_name} size={22} />
                      <span>{u.display_name}</span>
                      <span className="truncate text-fg-subtle">{u.email}</span>
                    </Item>
                  ))}
                </Command.Group>
              ) : null}
              {groups.data?.data.length ? (
                <Command.Group heading="Groups">
                  {groups.data.data.map((g) => (
                    <Item key={g.id} onSelect={() => go(`/groups/${g.id}`)}>
                      <UsersRound className="size-4 text-fg-muted" />
                      <span>{g.name}</span>
                      <span className="text-fg-subtle">{g.member_count} members</span>
                    </Item>
                  ))}
                </Command.Group>
              ) : null}
              <Command.Group heading="Go to">
                {NAV.flatMap((s) => s.items)
                  .filter((i) => !i.soon && i.label.toLowerCase().includes(search.toLowerCase()))
                  .map((i) => (
                    <Item key={i.href} onSelect={() => go(i.href)}>
                      <i.icon className="size-4 text-fg-muted" />
                      {i.label}
                      {i.shortcut ? <span className="ml-auto font-mono text-[11px] text-fg-subtle">{i.shortcut}</span> : null}
                    </Item>
                  ))}
              </Command.Group>
              <Command.Group heading="Actions">
                {"new user".includes(search.toLowerCase()) || !search ? (
                  <Item onSelect={() => go("/users?new=1")}>
                    <UserIcon className="size-4 text-fg-muted" /> Create user…
                  </Item>
                ) : null}
                {"sign out".includes(search.toLowerCase()) || !search ? (
                  <Item
                    onSelect={async () => {
                      await bffAuth("logout");
                      window.location.assign("/login");
                    }}
                  >
                    <LogOut className="size-4 text-fg-muted" /> Sign out
                  </Item>
                ) : null}
              </Command.Group>
            </Command.List>
          </Command>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

function Item({ children, onSelect }: { children: React.ReactNode; onSelect: () => void }) {
  return (
    <Command.Item
      onSelect={onSelect}
      className="flex cursor-default items-center gap-2.5 rounded-md px-3 py-2 text-[13px] data-[selected=true]:bg-bg-muted"
    >
      {children}
    </Command.Item>
  );
}
