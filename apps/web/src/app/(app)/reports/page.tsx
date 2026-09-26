"use client";

import { useQuery } from "@tanstack/react-query";
import { Download, FileBarChart } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { cn, formatDateTime } from "@/lib/utils";

type Kind = "mfa_coverage" | "admin_access" | "dormant_accounts" | "device_compliance" | "app_access" | "agent_tool_access";

const label = (k: string) => k.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
const cell = (v: string | number | boolean | null) => (v === true ? "Yes" : v === false ? "No" : v === null || v === "" ? "—" : /^\d{4}-\d\d-\d\dT/.test(String(v)) ? formatDateTime(String(v)) : String(v));

function ReportsView() {
  const params = useSearchParams();
  const router = useRouter();
  const kind = (params.get("kind") ?? "mfa_coverage") as Kind;
  const days = Number(params.get("days") ?? 90);
  const kinds = useQuery({ queryKey: ["reports"], queryFn: () => unwrap(api.GET("/v1/reports")) });
  const report = useQuery({ queryKey: ["report", kind, days], queryFn: () => unwrap(api.GET("/v1/reports/{kind}", { params: { path: { kind }, query: { format: "json", days } } })) });
  const set = (k: Kind, d = days) => router.replace(`/reports?kind=${k}${k === "dormant_accounts" ? `&days=${d}` : ""}`);
  const r = report.data && typeof report.data === "object" ? report.data : null;
  return (
    <>
      <PageHeader title="Reports" description="Evidence for audits (SOC 2, ISO 27001): generated from live data, downloadable as CSV. Every report you generate is recorded in the audit log." />
      <div className="mb-4 flex flex-wrap gap-2">
        {(kinds.data?.data ?? []).map((k) => (
          <button key={k.kind} onClick={() => set(k.kind as Kind)} title={k.description} className={cn("rounded-full border px-3 py-1 text-[13px]", kind === k.kind ? "border-primary bg-primary-soft/50 font-medium" : "border-border text-fg-muted hover:bg-bg-subtle")}>
            {k.title}
          </button>
        ))}
      </div>
      <ErrorBanner error={report.error} />
      {!r ? (
        <Skeleton className="h-60" />
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <div className="min-w-0 flex-1">
              <h2 className="text-[15px] font-semibold">{r.title}</h2>
              <p className="text-[13px] text-fg-muted">
                {r.description} Generated {formatDateTime(r.generated_at)}.
              </p>
            </div>
            {kind === "dormant_accounts" ? (
              <Select aria-label="No sign-in for" value={String(days)} onChange={(e) => set(kind, Number(e.target.value))}>
                {[30, 60, 90, 180, 365].map((d) => (
                  <option key={d} value={d}>
                    No sign-in for {d} days
                  </option>
                ))}
              </Select>
            ) : null}
            <a href={`/bff/v1/reports/${kind}?format=csv&days=${days}`}>
              <Button>
                <Download /> Download CSV
              </Button>
            </a>
          </div>
          <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            {Object.entries(r.summary).map(([k, v]) => (
              <Card key={k} className="p-3">
                <p className="text-xs text-fg-muted">{label(k)}</p>
                <p className="text-lg font-semibold tabular">{typeof v === "number" && k.endsWith("percent") ? `${v}%` : v}</p>
              </Card>
            ))}
          </div>
          <Card className="overflow-x-auto">
            {r.rows.length ? (
              <Table>
                <THead>
                  <tr>
                    {r.columns.map((c) => (
                      <TH key={c}>{label(c)}</TH>
                    ))}
                  </tr>
                </THead>
                <tbody>
                  {r.rows.slice(0, 500).map((row, i) => (
                    <TR key={i}>
                      {row.map((v, j) => (
                        <TD key={j} className="whitespace-nowrap">
                          {cell(v)}
                        </TD>
                      ))}
                    </TR>
                  ))}
                </tbody>
              </Table>
            ) : (
              <EmptyState icon={<FileBarChart />} title="Nothing to report" description="This report has no rows right now." />
            )}
            {r.rows.length > 500 ? <p className="p-3 text-xs text-fg-muted">Showing 500 of {r.rows.length} rows. The CSV has them all.</p> : null}
          </Card>
        </>
      )}
    </>
  );
}

export default function ReportsPage() {
  return (
    <Suspense>
      <ReportsView />
    </Suspense>
  );
}
