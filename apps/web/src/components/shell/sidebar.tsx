"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Logo } from "@/components/logo";
import { cn } from "@/lib/utils";
import { useMe } from "@/lib/queries";
import { NAV } from "./nav";

export function Sidebar() {
  const path = usePathname();
  const { data: me } = useMe();
  const isActive = (href: string) => (href === "/" ? path === "/" : path === href || path.startsWith(href + "/"));

  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-border bg-bg-subtle md:flex">
      <div className="flex h-14 items-center border-b border-border px-4">
        <Logo />
      </div>
      <div className="border-b border-border px-4 py-2.5">
        <p className="truncate text-[13px] font-medium">{me?.organization.name ?? "…"}</p>
        <p className="truncate text-xs text-fg-subtle">{me?.organization.slug}</p>
      </div>
      <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label="Main">
        {NAV.map((section, i) => (
          <div key={i} className="mb-4">
            {section.title ? (
              <p className="mb-1 px-2 text-[11px] font-medium uppercase tracking-wide text-fg-subtle">{section.title}</p>
            ) : null}
            {section.items.map((item) =>
              item.soon ? (
                <span
                  key={item.href}
                  className="flex items-center gap-2 rounded-md px-2 py-1.5 text-[13px] text-fg-subtle"
                  title={`Coming in Release ${item.soon}`}
                >
                  <item.icon className="size-4" />
                  {item.label}
                  <span className="ml-auto rounded bg-bg-muted px-1 text-[10px] font-medium">Soon</span>
                </span>
              ) : (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={isActive(item.href) ? "page" : undefined}
                  className={cn(
                    "flex items-center gap-2 rounded-md px-2 py-1.5 text-[13px] font-medium transition-colors",
                    isActive(item.href) ? "bg-bg text-fg shadow-card" : "text-fg-muted hover:bg-bg-muted hover:text-fg",
                  )}
                >
                  <item.icon className="size-4" />
                  {item.label}
                </Link>
              ),
            )}
          </div>
        ))}
      </nav>
    </aside>
  );
}
