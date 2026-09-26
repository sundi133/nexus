"use client";

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ScrollText, ShieldAlert, ShieldCheck, X } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { ActivityList } from "@/components/features/activity";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/input";
import { Card, EmptyState, PageHeader, Skeleton } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { pluralize, timeAgo } from "@/lib/utils";
import { useCan } from "@/lib/queries";

const TYPES = [
  ["", "All events"],
  ["auth.*", "Authentication"],
  ["user.*", "User changes"],
  ["group.*", "Group changes"],
  ["session.*", "Sessions"],
  ["org.*", "Organization"],
] as const;

function AuditView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const filters = {
    type: params.get("type") ?? undefined,
    outcome: (params.get("outcome") as "success" | "failure" | "denied" | null) ?? undefined,
  };
  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    router.replace(`${pathname}?${next}`);
  };

  const q = useInfiniteQuery({
    queryKey: ["audit", filters],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => unwrap(api.GET("/v1/audit/events", { params: { query: { ...filters, cursor: pageParam, limit: 50 } } })),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    refetchInterval: 15_000,
  });
  const events = q.data?.pages.flatMap((p) => p.data) ?? [];

  return (
    <>
      <PageHeader title="Audit log" description="Every change and sign-in, immutable. Click a row to see the full event." />
      <IntegrityCard />
      <div className="mb-3 flex flex-wrap gap-2">
        <Select value={filters.type ?? ""} onChange={(e) => setParam("type", e.target.value)} aria-label="Event type">
          {TYPES.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </Select>
        <Select value={filters.outcome ?? ""} onChange={(e) => setParam("outcome", e.target.value)} aria-label="Outcome">
          <option value="">Any outcome</option>
          <option value="success">Success</option>
          <option value="failure">Failure</option>
          <option value="denied">Denied</option>
        </Select>
        {filters.type || filters.outcome ? (
          <Button variant="ghost" size="sm" onClick={() => router.replace(pathname)}>
            <X /> Clear
          </Button>
        ) : null}
      </div>
      <Card className="overflow-hidden">
        {q.isPending ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <Skeleton key={i} className="h-7" />
            ))}
          </div>
        ) : events.length ? (
          <ActivityList events={events} />
        ) : (
          <EmptyState icon={<ScrollText />} title="No matching events" />
        )}
        {q.hasNextPage ? (
          <div className="border-t border-border p-2 text-center">
            <Button variant="ghost" size="sm" onClick={() => q.fetchNextPage()} loading={q.isFetchingNextPage}>
              Load older events
            </Button>
          </div>
        ) : null}
      </Card>
    </>
  );
}

export default function AuditPage() {
  return (
    <Suspense>
      <AuditView />
    </Suspense>
  );
}

/** The hash chain's state: sealed blocks, the latest digest, and the result of recomputing it (AUD-05). */
function IntegrityCard() {
  const qc = useQueryClient();
  const can = useCan();
  const v = useQuery({ queryKey: ["audit-integrity"], queryFn: () => unwrap(api.GET("/v1/audit/integrity")), staleTime: 60_000 });
  const seal = useMutation({ mutationFn: () => unwrap(api.POST("/v1/audit/seal")), onSuccess: () => qc.invalidateQueries({ queryKey: ["audit-integrity"] }) });
  if (!v.data) return null;
  const d = v.data;
  return (
    <Card className={`mb-4 flex flex-wrap items-center gap-3 p-4 text-[13px] ${d.ok ? "" : "border-danger/40 bg-danger-soft"}`}>
      {d.ok ? <ShieldCheck className="size-5 text-success" /> : <ShieldAlert className="size-5 text-danger" />}
      <div className="min-w-0 flex-1">
        <p className="font-medium">
          {!d.ok ? "The audit log failed its integrity check" : d.head ? "Audit log verified: nothing has been changed or removed" : "The audit log hasn't been sealed yet"}
        </p>
        <p className="text-xs text-fg-muted">
          {!d.ok && d.problem
            ? d.problem.detail
            : d.head
              ? `${pluralize(d.events_checked, "event")} in ${pluralize(d.blocks_checked, "sealed block")}${d.pruned_blocks ? ` (${d.pruned_blocks} past retention)` : ""} · last sealed ${timeAgo(d.head.sealed_at)} · ${d.unsealed_events} newer, sealed hourly · kept ${d.retention_days} days`
              : "Events are sealed into a hash chain every hour."}
        </p>
        {d.head ? (
          <p className="mt-0.5 truncate font-mono text-[11px] text-fg-subtle" title="Compare with the audit.sealed events in your SIEM or archive">
            Latest digest {d.head.digest}
          </p>
        ) : null}
      </div>
      {can("org:manage") && d.unsealed_events ? (
        <Button size="sm" loading={seal.isPending} onClick={() => seal.mutate()}>
          Seal now
        </Button>
      ) : null}
    </Card>
  );
}
