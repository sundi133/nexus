"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { useLiveUpdates } from "@/lib/stream";
import { useMe } from "@/lib/queries";
import { CommandPalette } from "./command-palette";
import { Sidebar } from "./sidebar";
import { Topbar } from "./topbar";

const GOTO: Record<string, string> = { o: "/", u: "/users", g: "/groups", a: "/audit" };

export function AppShell({ children }: { children: React.ReactNode }) {
  const [palette, setPalette] = useState(false);
  const router = useRouter();
  const pendingG = useRef(0);
  const me = useMe();
  useLiveUpdates();

  // Keyboard-first (docs/UI.md §1): ⌘K palette, "g u" style jumps, "/" focuses search.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      const typing = t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName);
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((v) => !v);
        return;
      }
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "/") {
        e.preventDefault();
        setPalette(true);
      } else if (e.key === "g") {
        pendingG.current = Date.now();
      } else if (Date.now() - pendingG.current < 800 && GOTO[e.key]) {
        router.push(GOTO[e.key]!);
        pendingG.current = 0;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [router]);

  if (me.isPending) {
    return <div className="flex h-dvh items-center justify-center text-[13px] text-fg-muted">Loading…</div>;
  }

  return (
    <div className="flex h-dvh">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onSearch={() => setPalette(true)} />
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-6xl px-4 py-6 md:px-8">{children}</div>
        </main>
      </div>
      <CommandPalette open={palette} onOpenChange={setPalette} />
    </div>
  );
}
