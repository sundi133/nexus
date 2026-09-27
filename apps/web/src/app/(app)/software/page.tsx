"use client";

import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, PackageSearch, Search } from "lucide-react";
import Link from "next/link";
import { Fragment, useDeferredValue, useState } from "react";
import { Input } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { pluralize } from "@/lib/utils";

const SOURCE: Record<string, string> = { app: "App", homebrew: "Homebrew", program: "Program", chocolatey: "Chocolatey", deb: "deb", rpm: "rpm" };

export default function SoftwarePage() {
  const [q, setQ] = useState("");
  const query = useDeferredValue(q.trim());
  const sw = useQuery({ queryKey: ["software", query], queryFn: () => unwrap(api.GET("/v1/software", { params: { query: { q: query || undefined, limit: 500 } } })) });
  const [open, setOpen] = useState<string | null>(null);

  return (
    <>
      <PageHeader title="Software" description="What's installed across your devices, from osquery, with the versions in use. Click a row to see which devices have it." />
      <div className="relative mb-4 max-w-sm">
        <Search className="absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-fg-subtle" aria-hidden />
        <Input className="pl-8" placeholder="Search software, e.g. chrome" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search software" />
      </div>
      {sw.isPending ? (
        <Skeleton className="h-64" />
      ) : !sw.data ? (
        <ErrorBanner error={sw.error} />
      ) : sw.data.devices_reporting === 0 ? (
        <Card>
          <EmptyState icon={<PackageSearch className="size-5" />} title="No software inventory yet" description="Devices report software once osquery is installed alongside the Nexus agent." />
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <p className="border-b border-border px-4 py-2 text-xs text-fg-muted">{pluralize(sw.data.devices_reporting, "device")} reporting · {pluralize(sw.data.data.length, "title")}{sw.data.data.length === 500 ? " (first 500)" : ""}</p>
          {sw.data.data.length ? (
            <Table>
              <THead>
                <tr>
                  <TH className="w-8" />
                  <TH>Name</TH>
                  <TH>Source</TH>
                  <TH className="text-right">Devices</TH>
                  <TH>Versions</TH>
                </tr>
              </THead>
              <tbody>
                {sw.data.data.map((s) => {
                  const key = `${s.name}\u0000${s.source}`;
                  return (
                    <Fragment key={key}>
                      <TR className="cursor-pointer" onClick={() => setOpen(open === key ? null : key)}>
                        <TD>
                          <button type="button" aria-expanded={open === key} aria-label={`Devices with ${s.name}`} className="text-fg-muted">
                            {open === key ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
                          </button>
                        </TD>
                        <TD className="font-medium">{s.name}</TD>
                        <TD className="text-fg-muted">{SOURCE[s.source] ?? s.source}</TD>
                        <TD className="text-right tabular-nums">{s.devices}</TD>
                        <TD className="font-mono text-xs text-fg-muted">
                          {s.versions.slice(0, 3).map((v) => `${v.version || "?"} (${v.devices})`).join(", ")}
                          {s.versions.length > 3 ? ` +${s.versions.length - 3}` : ""}
                        </TD>
                      </TR>
                      {open === key ? (
                        <tr className="border-b border-border bg-bg-subtle/60">
                          <td />
                          <td colSpan={4} className="px-3 py-2">
                            <WhoHas name={s.name} source={s.source} />
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </Table>
          ) : (
            <EmptyState title={`Nothing matches “${query}”`} />
          )}
        </Card>
      )}
    </>
  );
}

function WhoHas({ name, source }: { name: string; source: string }) {
  const who = useQuery({ queryKey: ["software-devices", name, source], queryFn: () => unwrap(api.GET("/v1/software/devices", { params: { query: { name, source } } })) });
  if (who.isPending) return <Skeleton className="h-6" />;
  if (!who.data) return <ErrorBanner error={who.error} />;
  return (
    <ul className="space-y-1 text-[13px]">
      {who.data.data.map((d) => (
        <li key={`${d.device_id}-${d.version}`} className="flex flex-wrap items-center gap-2">
          <Link href={`/devices/${d.device_id}`} className="font-medium hover:underline">
            {d.hostname}
          </Link>
          <span className="text-fg-muted">{d.user_email ?? "no user assigned"}</span>
          <code className="font-mono text-xs text-fg-subtle">{d.version || "no version"}</code>
        </li>
      ))}
    </ul>
  );
}
