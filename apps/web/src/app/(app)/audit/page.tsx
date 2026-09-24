"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { ScrollText, X } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { ActivityList } from "@/components/features/activity";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/input";
import { Card, EmptyState, PageHeader, Skeleton } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";

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
