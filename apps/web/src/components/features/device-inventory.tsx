"use client";

import { useQuery } from "@tanstack/react-query";
import { Database } from "lucide-react";
import { useState } from "react";
import { orderedColumns, RowsTable, TABLE_TITLES } from "@/components/features/osquery-bits";
import { Card, CardHeader, EmptyState, ErrorBanner, Skeleton } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { cn, formatDateTime } from "@/lib/utils";

/** A device's osquery inventory (the scheduled pack). */
export function DeviceInventory({ deviceId, hostname }: { deviceId: string; hostname: string }) {
  const inv = useQuery({ queryKey: ["device-osquery", deviceId], queryFn: () => unwrap(api.GET("/v1/devices/{id}/osquery", { params: { path: { id: deviceId } } })) });
  const [table, setTable] = useState("software");

  if (inv.isPending) return <Skeleton className="h-40" />;
  if (!inv.data) return <ErrorBanner error={inv.error} />;
  const d = inv.data;
  if (d.status !== "installed") {
    return (
      <Card>
        <EmptyState
          icon={<Database className="size-5" />}
          title={d.status === "not_installed" ? "osquery isn't installed on this device" : "No inventory yet"}
          description={
            d.status === "not_installed"
              ? "Install osquery alongside the Nexus agent (see the agent docs) to see software, listening ports, USB devices, browser extensions and startup items."
              : "The agent sends its first osquery inventory within a few minutes of starting, if osquery is installed."
          }
        />
      </Card>
    );
  }
  const current = d.tables.find((t) => t.name === table) ?? d.tables[0];
  return (
    <Card className="overflow-hidden">
      <CardHeader title="Inventory" description={`From osquery ${d.version ?? ""}${d.collected_at ? `, collected ${formatDateTime(d.collected_at)}` : ""}. Refreshed every 6 hours, or with the Refresh action.`} />
      <div className="flex flex-wrap gap-1 border-b border-border px-4 py-2" role="tablist" aria-label="Inventory tables">
        {d.tables.map((t) => (
          <button
            key={t.name}
            role="tab"
            aria-selected={current?.name === t.name}
            onClick={() => setTable(t.name)}
            className={cn("rounded-md px-2.5 py-1 text-xs font-medium", current?.name === t.name ? "bg-primary-soft text-primary" : "text-fg-muted hover:bg-bg-subtle")}
          >
            {TABLE_TITLES[t.name]?.title ?? t.name} <span className="tabular-nums text-fg-subtle">{t.error ? "!" : t.rows.length}</span>
          </button>
        ))}
      </div>
      {current ? (
        current.error ? (
          <p className="px-4 py-3 text-[13px] text-danger">osquery couldn&apos;t read this on {hostname}: {current.error}</p>
        ) : (
          <>
            {current.truncated ? <p className="border-b border-border px-4 py-2 text-xs text-warning">Only the first {current.rows.length.toLocaleString()} rows were collected.</p> : null}
            <RowsTable rows={current.rows} columns={orderedColumns(current.name, current.rows)} file={`${hostname}-${current.name}`} empty={`No ${TABLE_TITLES[current.name]?.title.toLowerCase() ?? "rows"}`} />
          </>
        )
      ) : (
        <EmptyState title="No tables reported" />
      )}
    </Card>
  );
}
