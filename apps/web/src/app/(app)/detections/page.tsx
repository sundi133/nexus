"use client";

import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { useState } from "react";
import { ProcessEventsTable } from "@/components/features/process-events";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { cn } from "@/lib/utils";

const LEVELS = [
  ["high", "High"],
  ["low", "Low"],
  ["info", "Info"],
  ["", "All"],
] as const;

export default function DetectionsPage() {
  const [severity, setSeverity] = useState<"high" | "low" | "info" | "">("high");
  const d = useQuery({ queryKey: ["detections", severity], queryFn: () => unwrap(api.GET("/v1/detections", { params: { query: { severity: severity || undefined, limit: 300 } } })), refetchInterval: 30_000 });
  return (
    <>
      <PageHeader
        title="Detections"
        description="From devices' real-time process events: AI tools (Cursor, Claude, Codex…) running network tools like curl or scp (high), starting shells (info), and programs run from temporary or downloads folders (low). High findings raise the alert “AI tool ran a network tool”."
        actions={
          <div className="inline-flex rounded-md border border-border p-0.5" role="radiogroup" aria-label="Severity">
            {LEVELS.map(([v, label]) => (
              <button key={v} type="button" role="radio" aria-checked={severity === v} onClick={() => setSeverity(v)} className={cn("rounded px-2.5 py-1 text-xs font-medium", severity === v ? "bg-primary text-white" : "text-fg-muted hover:bg-bg-subtle")}>
                {label}
              </button>
            ))}
          </div>
        }
      />
      {d.isPending ? (
        <Skeleton className="h-64" />
      ) : !d.data ? (
        <ErrorBanner error={d.error} />
      ) : d.data.data.length ? (
        <Card className="overflow-hidden">
          <ProcessEventsTable events={d.data.data} showDevice />
        </Card>
      ) : (
        <Card>
          <EmptyState icon={<ShieldAlert className="size-5" />} title="Nothing found" description="Detections appear here once process events are on (Settings → Organization) and devices report them." />
        </Card>
      )}
    </>
  );
}
