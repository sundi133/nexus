"use client";

import { LogOut, Search, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Avatar, Kbd } from "@/components/ui/misc";
import { Menu, MenuContent, MenuItem, MenuLabel, MenuSeparator, MenuTrigger } from "@/components/ui/overlay";
import { bffAuth } from "@/lib/api";
import { useMe } from "@/lib/queries";
import { ROLE_LABELS } from "@/lib/utils";
import { InboxButton } from "./inbox";

export function Topbar({ onSearch }: { onSearch: () => void }) {
  const { data: me } = useMe();
  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border bg-bg px-4 md:px-6">
      <button
        onClick={onSearch}
        className="flex h-8 w-full max-w-md items-center gap-2 rounded-md border border-border bg-bg-subtle px-2.5 text-[13px] text-fg-subtle hover:border-border-strong"
      >
        <Search className="size-4" />
        Search users, groups, pages…
        <span className="ml-auto flex gap-0.5">
          <Kbd>⌘</Kbd>
          <Kbd>K</Kbd>
        </span>
      </button>
      <div className="ml-auto flex items-center gap-1">
        <InboxButton />
        <Menu>
          <MenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label="Account menu">
              <Avatar name={me?.user.display_name ?? "?"} size={26} />
            </Button>
          </MenuTrigger>
          <MenuContent>
            <MenuLabel>{me?.user.email}</MenuLabel>
            <div className="px-2 pb-1.5 text-xs text-fg-muted">{me?.roles.map((r) => ROLE_LABELS[r]).join(", ") || "Member"}</div>
            <MenuSeparator />
            <MenuItem>
              <Link href="/settings/security" className="flex w-full items-center gap-2">
                <ShieldCheck /> My security
              </Link>
            </MenuItem>
            <MenuItem
              onSelect={async () => {
                await bffAuth("logout");
                window.location.assign("/login");
              }}
            >
              <LogOut /> Sign out
            </MenuItem>
          </MenuContent>
        </Menu>
      </div>
    </header>
  );
}
