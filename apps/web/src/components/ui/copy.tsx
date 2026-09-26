"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

/** A read-only value with a copy button (client IDs, URLs, secrets). */
export function CopyField({ label, value, secret, className }: { label?: string; value: string; secret?: boolean; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className={className}>
      {label ? <p className="mb-1 text-xs font-medium text-fg-muted">{label}</p> : null}
      <div className={cn("flex items-center gap-2 rounded-md border border-border bg-bg-subtle px-2.5 py-1.5", secret && "border-warning/40 bg-warning-soft")}>
        <code className="min-w-0 flex-1 truncate font-mono text-xs" title={value}>
          {value}
        </code>
        <button
          type="button"
          aria-label={`Copy ${label ?? "value"}`}
          className="shrink-0 rounded p-1 text-fg-muted hover:bg-bg-muted hover:text-fg"
          onClick={async () => {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
        </button>
      </div>
    </div>
  );
}
