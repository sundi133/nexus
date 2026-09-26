"use client";

import type { Schemas } from "@nexus/api-client";
import { TriangleAlert } from "lucide-react";
import { useState } from "react";
import { CopyField } from "@/components/ui/copy";
import { cn } from "@/lib/utils";

type Install = Schemas["EnrollmentInstructions"];
const TABS = [
  { key: "macos", label: "macOS" },
  { key: "windows", label: "Windows" },
  { key: "linux", label: "Linux" },
] as const;

/** Per-OS install commands for a freshly created enrollment token (shown once). */
export function EnrollInstructions({ install }: { install: Install }) {
  const [os, setOs] = useState<(typeof TABS)[number]["key"]>("macos");
  return (
    <div className="space-y-3">
      <div className="flex gap-1 rounded-md bg-bg-subtle p-1" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={os === t.key}
            onClick={() => setOs(t.key)}
            className={cn("flex-1 rounded px-2 py-1 text-[13px] font-medium", os === t.key ? "bg-bg shadow-card" : "text-fg-muted hover:text-fg")}
          >
            {t.label}
          </button>
        ))}
      </div>
      <ol className="list-decimal space-y-2 pl-4 text-[13px]">
        <li>
          Install the Nexus agent. <span className="text-fg-muted">Signed installers are coming; for now build it with </span>
          <code className="rounded bg-bg-subtle px-1 font-mono text-xs">go build ./agent/cmd/nexus-agent</code>
        </li>
        <li>
          {os === "windows" ? "In an administrator PowerShell, run:" : "In a terminal, run:"}
          <CopyField className="mt-1.5" value={install.commands[os]} />
        </li>
        <li>
          Start reporting: <code className="rounded bg-bg-subtle px-1 font-mono text-xs">{os === "windows" ? "nexus-agent.exe run" : "sudo nexus-agent run"}</code>
        </li>
      </ol>
      <p className="flex items-start gap-1.5 text-xs text-warning">
        <TriangleAlert className="mt-px size-3.5 shrink-0" /> The token is only shown now. Treat it like a password: anyone with it can enroll a device into your organization.
      </p>
    </div>
  );
}
