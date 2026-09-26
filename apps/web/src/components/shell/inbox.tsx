"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Dialog as D } from "radix-ui";
import { Bell, CheckCheck } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { SheetContent } from "@/components/ui/overlay";
import { EmptyState } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { qk, useInbox } from "@/lib/queries";
import { cn, timeAgo } from "@/lib/utils";

const DOT = { critical: "bg-danger", warning: "bg-warning", info: "bg-primary" } as const;

/** The notification inbox, the same records Nexus Mobile shows (ARCHITECTURE §11). */
export function InboxButton() {
  const { data } = useInbox();
  const qc = useQueryClient();
  const markAll = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/me/notifications/read-all")),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.inbox }),
  });
  const markRead = useMutation({
    mutationFn: (id: string) => unwrap(api.POST("/v1/me/notifications/{id}/read", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.inbox }),
  });
  const unread = data?.unread_count ?? 0;

  return (
    <D.Root>
      <D.Trigger asChild>
        <Button variant="ghost" size="icon" aria-label={`Notifications${unread ? `, ${unread} unread` : ""}`} className="relative">
          <Bell />
          {unread > 0 ? (
            <span className="absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[10px] font-semibold text-white">
              {unread > 9 ? "9+" : unread}
            </span>
          ) : null}
        </Button>
      </D.Trigger>
      <SheetContent title="Notifications">
        <div className="flex items-center justify-between border-b border-border px-4 py-2">
          <span className="text-xs text-fg-muted">{unread} unread</span>
          <Button variant="ghost" size="sm" onClick={() => markAll.mutate()} disabled={!unread}>
            <CheckCheck /> Mark all read
          </Button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {!data?.data.length ? (
            <EmptyState icon={<Bell />} title="You're all caught up" description="Security alerts, approvals and account changes show up here and on your phone." />
          ) : (
            <ul>
              {data.data.map((n) => {
                const body = (
                  <div className="flex gap-3 px-4 py-3">
                    <span className={cn("mt-1.5 size-2 shrink-0 rounded-full", n.read ? "bg-transparent" : DOT[n.severity])} aria-hidden />
                    <div className="min-w-0 flex-1">
                      <p className={cn("text-[13px]", n.read ? "text-fg-muted" : "font-medium text-fg")}>{n.title}</p>
                      {n.body ? <p className="mt-0.5 text-[13px] text-fg-muted">{n.body}</p> : null}
                      <p className="mt-1 text-xs text-fg-subtle">{timeAgo(n.created_at)}</p>
                    </div>
                  </div>
                );
                return (
                  <li key={n.id} className="border-b border-border hover:bg-bg-subtle">
                    {n.link ? (
                      <D.Close asChild>
                        <Link href={n.link} onClick={() => !n.read && markRead.mutate(n.id)} className="block">
                          {body}
                        </Link>
                      </D.Close>
                    ) : (
                      <button className="block w-full text-left" onClick={() => !n.read && markRead.mutate(n.id)}>
                        {body}
                      </button>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </SheetContent>
    </D.Root>
  );
}
