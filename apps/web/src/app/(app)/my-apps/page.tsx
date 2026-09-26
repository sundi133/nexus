"use client";

import { useQuery } from "@tanstack/react-query";
import { AppWindow, ExternalLink } from "lucide-react";
import { useState } from "react";
import { AppIcon } from "@/components/features/app-icon";
import { Input } from "@/components/ui/input";
import { EmptyState, PageHeader, Skeleton } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";

/** The app launcher every employee sees (SPEC PORT-01). */
export default function MyAppsPage() {
  const [q, setQ] = useState("");
  const apps = useQuery({ queryKey: ["my-apps"], queryFn: () => unwrap(api.GET("/v1/me/apps")) });
  const list = (apps.data?.data ?? []).filter((a) => a.name.toLowerCase().includes(q.toLowerCase()));

  return (
    <>
      <PageHeader title="My apps" description="Everything you can sign in to with Nexus." />
      {apps.data?.data.length ? (
        <Input className="mb-4 max-w-xs" placeholder="Search apps" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search apps" />
      ) : null}
      {apps.isPending ? (
        <Skeleton className="h-28" />
      ) : !apps.data?.data.length ? (
        <EmptyState icon={<AppWindow />} title="No apps yet" description="When your administrator gives you access to an app, it shows up here." />
      ) : (
        <ul className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {list.map((a) => {
            const inner = (
              <>
                <AppIcon name={a.name} size={44} />
                <span className="mt-2 line-clamp-2 text-center text-[13px] font-medium">{a.name}</span>
                {a.launch_url ? <ExternalLink className="absolute right-2 top-2 size-3 text-fg-subtle opacity-0 group-hover:opacity-100" /> : null}
              </>
            );
            return (
              <li key={a.id}>
                {a.launch_url ? (
                  <a
                    href={a.launch_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="group relative flex flex-col items-center rounded-lg border border-border bg-bg p-4 shadow-card transition-colors hover:border-primary"
                  >
                    {inner}
                  </a>
                ) : (
                  <div className="relative flex flex-col items-center rounded-lg border border-dashed border-border p-4 text-fg-muted" title="Open this app directly and choose 'Sign in with SSO'">
                    {inner}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </>
  );
}
