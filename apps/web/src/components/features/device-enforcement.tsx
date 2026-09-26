"use client";

import { useQuery } from "@tanstack/react-query";
import { EventsTable } from "@/components/features/enforcement-bits";
import { Card, CardHeader, StatusPill } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";

/** A device's block rules: whether it applied the current ones, and what it stopped. */
export function DeviceEnforcement({ deviceId }: { deviceId: string }) {
  const st = useQuery({ queryKey: ["device-enforcement", deviceId], queryFn: () => unwrap(api.GET("/v1/devices/{id}/enforcement", { params: { path: { id: deviceId } } })) });
  const ev = useQuery({ queryKey: ["enforcement-events", deviceId], queryFn: () => unwrap(api.GET("/v1/enforcement/events", { params: { query: { device_id: deviceId, limit: 50 } } })) });
  if (!st.data) return null;
  const s = st.data;
  if (!s.rules.length && !ev.data?.data.length) return null;
  return (
    <Card className="overflow-hidden">
      <CardHeader
        title="Block rules"
        description={
          <span className="flex flex-wrap items-center gap-2">
            {s.in_sync ? <StatusPill tone="success">Up to date</StatusPill> : <StatusPill tone="warning">Waiting for the device</StatusPill>}
            {s.rules.length} {s.rules.length === 1 ? "rule applies" : "rules apply"}
            {s.status ? <span className={s.status.startsWith("couldn") ? "text-danger" : "text-fg-muted"}>· {s.status}</span> : null}
          </span>
        }
      />
      <EventsTable events={ev.data?.data ?? []} />
    </Card>
  );
}
