"use client";

import type { Schemas } from "@nexus/api-client";
import { CircleCheck, CircleHelp, CircleMinus, CircleX, Laptop, Monitor, Terminal, Wrench } from "lucide-react";
import { StatusPill } from "@/components/ui/misc";
import { cn } from "@/lib/utils";

type Device = Schemas["Device"];
type Check = Schemas["DeviceCheck"];

export const PLATFORM_LABEL = { macos: "macOS", windows: "Windows", linux: "Linux" } as const;

export function PlatformIcon({ platform, className }: { platform: Device["platform"]; className?: string }) {
  const Icon = platform === "macos" ? Laptop : platform === "windows" ? Monitor : Terminal;
  return <Icon className={cn("size-4 text-fg-muted", className)} aria-label={PLATFORM_LABEL[platform]} />;
}

export function ComplianceBadge({ compliance, graceUntil }: { compliance: Device["compliance"]; graceUntil?: string | null }) {
  if (compliance === "compliant" && graceUntil) return <StatusPill tone="warning">Fix by {new Date(graceUntil).toLocaleDateString(undefined, { month: "short", day: "numeric" })}</StatusPill>;
  if (compliance === "compliant") return <StatusPill tone="success">Compliant</StatusPill>;
  if (compliance === "non_compliant") return <StatusPill tone="danger">Not compliant</StatusPill>;
  return <StatusPill tone="warning">Unknown</StatusPill>;
}

export function OnlineDot({ online }: { online: boolean }) {
  return <span className={cn("inline-block size-2 rounded-full", online ? "bg-success" : "bg-border-strong")} aria-label={online ? "Online" : "Offline"} />;
}

const STATUS = {
  pass: { icon: CircleCheck, cls: "text-success", label: "Pass" },
  fail: { icon: CircleX, cls: "text-danger", label: "Failing" },
  unknown: { icon: CircleHelp, cls: "text-warning", label: "Unknown" },
  not_applicable: { icon: CircleMinus, cls: "text-fg-subtle", label: "Not applicable" },
} as const;

/** Each policy check with its result, why it matters, and how to fix it (docs/UI.md "Why?"). */
export function CheckList({ checks }: { checks: Check[] }) {
  if (!checks.length) return <p className="px-4 py-6 text-center text-[13px] text-fg-muted">Waiting for the device&apos;s first report.</p>;
  return (
    <ul className="divide-y divide-border">
      {checks.map((c) => {
        const s = STATUS[c.status];
        return (
          <li key={c.key} className="flex gap-3 px-4 py-3">
            <s.icon className={cn("mt-0.5 size-4 shrink-0", s.cls)} aria-label={s.label} />
            <div className="min-w-0 flex-1 text-[13px]">
              <p className="font-medium">
                {c.title} <span className="font-normal text-fg-muted">· {c.detail}</span>
                {!c.enforced ? <span className="ml-1.5 rounded bg-bg-muted px-1.5 py-0.5 text-[11px] font-normal text-fg-muted">audit only</span> : null}
              </p>
              {c.grace_until ? (
                <p className="mt-0.5 text-xs font-medium text-warning">
                  Fix by {new Date(c.grace_until).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}: after that this device stops counting as compliant.
                </p>
              ) : null}
              {c.status === "fail" || c.status === "unknown" ? <p className="mt-0.5 text-xs text-fg-subtle">{c.why}</p> : null}
              {c.fix ? (
                <p className="mt-2 flex items-start gap-1.5 rounded-md bg-bg-subtle px-2.5 py-2 text-xs">
                  <Wrench className="mt-px size-3.5 shrink-0 text-fg-muted" />
                  <span>{c.fix}</span>
                </p>
              ) : null}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

const CHECK_TITLES: Record<string, string> = {
  disk_encryption: "Disk encryption",
  firewall: "Firewall",
  screen_lock: "Screen lock",
  os_version: "OS version",
  system_integrity: "System integrity",
};
export const checkTitle = (k: string) => CHECK_TITLES[k] ?? k;
