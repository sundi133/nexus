"use client";

import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { useDeferredValue, useState } from "react";
import { ProcessEventsTable } from "@/components/features/process-events";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, Skeleton } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { cn } from "@/lib/utils";

/** A device's real-time process events. */
export function DeviceProcesses({ deviceId }: { deviceId: string }) {
  const [onlyFindings, setOnlyFindings] = useState(false);
  const [q, setQ] = useState("");
  const query = useDeferredValue(q.trim());
  const ev = useQuery({
    queryKey: ["process-events", deviceId, onlyFindings, query],
    queryFn: () => unwrap(api.GET("/v1/devices/{id}/process-events", { params: { path: { id: deviceId }, query: { detections: onlyFindings || undefined, q: query || undefined, limit: 300 } } })),
    refetchInterval: 15_000,
  });
  if (ev.isPending) return <Skeleton className="h-40" />;
  if (!ev.data) return <ErrorBanner error={ev.error} />;
  if (!ev.data.status && !ev.data.data.length)
    return (
      <Card>
        <EmptyState icon={<Activity className="size-5" />} title="No process events" description="Turn on “Collect real-time process events” under Settings → Organization. Devices start reporting within a minute." />
      </Card>
    );
  return (
    <Card className="overflow-hidden">
      <CardHeader
        title="Processes"
        description={<span className={ev.data.status.startsWith("running") ? undefined : "text-warning"}>{ev.data.status || "Waiting for the device"}</span>}
        actions={
          <div className="flex items-center gap-2">
            <Input className="w-48" placeholder="Filter" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter events" />
            <div className="inline-flex shrink-0 rounded-md border border-border p-0.5" role="radiogroup" aria-label="Which events">
              {([false, true] as const).map((v) => (
                <button key={String(v)} type="button" role="radio" aria-checked={onlyFindings === v} onClick={() => setOnlyFindings(v)} className={cn("whitespace-nowrap rounded px-2.5 py-1 text-xs font-medium", onlyFindings === v ? "bg-primary text-white" : "text-fg-muted hover:bg-bg-subtle")}>
                  {v ? "Findings" : "All"}
                </button>
              ))}
            </div>
          </div>
        }
      />
      <ProcessEventsTable events={ev.data.data} />
    </Card>
  );
}
