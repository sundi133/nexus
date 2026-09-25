"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, ChevronLeft, Download, X } from "lucide-react";
import Link from "next/link";
import { use, useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/features/confirm-action";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Card, EmptyState, ErrorBanner, Skeleton, StatusPill } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, timeAgo } from "@/lib/utils";

type Item = Schemas["AccessReviewItem"];

export default function ReviewPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const qc = useQueryClient();
  const can = useCan();
  const withStepUp = useStepUp();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [closing, setClosing] = useState(false);
  const data = useQuery({ queryKey: ["access-review", id], queryFn: () => unwrap(api.GET("/v1/access-reviews/{id}", { params: { path: { id } } })) });
  const decide = useMutation({
    mutationFn: (items: { id: string; decision: "keep" | "revoke" }[]) => unwrap(api.POST("/v1/access-reviews/{id}/decisions", { params: { path: { id } }, body: { items } })),
    onSuccess: (r) => (qc.setQueryData(["access-review", id], r), qc.invalidateQueries({ queryKey: ["access-reviews"] }), setSelected(new Set())),
  });
  const close = async () => {
    const r = await withStepUp(() => unwrap(api.POST("/v1/access-reviews/{id}/close", { params: { path: { id } } })));
    qc.setQueryData(["access-review", id], r);
    qc.invalidateQueries({ queryKey: ["access-reviews"] });
    toast.success(`Closed: ${r.review.summary.revoked ?? 0} revoked, ${r.review.summary.kept ?? 0} kept`);
    return r;
  };

  if (data.isPending) return <Skeleton className="h-60" />;
  if (!data.data) return <ErrorBanner error={data.error} />;
  const { review: r, items } = data.data;
  const decidable = items.filter((i) => i.you_can_decide);
  const toggle = (iid: string) => setSelected((s) => (s.has(iid) ? (s.delete(iid), new Set(s)) : new Set(s.add(iid))));
  const bulk = (decision: "keep" | "revoke") => decide.mutate([...selected].map((iid) => ({ id: iid, decision })));
  const open = r.status === "open";

  return (
    <>
      <Link href="/access-reviews" className="mb-3 inline-flex items-center gap-1 text-[13px] text-fg-muted hover:text-fg">
        <ChevronLeft className="size-4" /> Access reviews
      </Link>
      <div className="mb-5 flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="flex flex-wrap items-center gap-2 text-xl font-semibold tracking-tight">
            {r.name} {open ? <StatusPill tone="primary">Open</StatusPill> : <StatusPill>Closed</StatusPill>}
          </h1>
          <p className="mt-0.5 text-[13px] text-fg-muted">
            Who has <span className="capitalize">{r.scope.name}</span> · {r.progress.decided} of {r.progress.total} decided · {open ? `due ${new Date(r.due_at).toLocaleDateString()}; undecided access is ${r.on_no_decision === "keep" ? "kept" : "revoked"}` : `closed ${timeAgo(r.closed_at!)}: ${r.summary.kept ?? 0} kept, ${r.summary.revoked ?? 0} revoked${r.summary.skipped ? `, ${r.summary.skipped} skipped` : ""}`}
          </p>
        </div>
        {can("access:manage") ? (
          <div className="flex gap-2">
            <a href={`/bff/v1/access-reviews/${id}/export`}>
              <Button>
                <Download /> Export CSV
              </Button>
            </a>
            {open ? (
              <Button variant="primary" onClick={() => setClosing(true)}>
                Close and apply
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>

      {open && decidable.length ? (
        <div className="mb-3 flex flex-wrap items-center gap-2 text-[13px]">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={selected.size === decidable.length} onChange={(e) => setSelected(e.target.checked ? new Set(decidable.map((i) => i.id)) : new Set())} /> Select all you can decide ({decidable.length})
          </label>
          {selected.size ? (
            <>
              <Button size="sm" variant="secondary" loading={decide.isPending} onClick={() => bulk("keep")}>
                <Check /> Keep {selected.size}
              </Button>
              <Button size="sm" variant="danger-outline" loading={decide.isPending} onClick={() => bulk("revoke")}>
                <X /> Revoke {selected.size}
              </Button>
            </>
          ) : null}
        </div>
      ) : null}
      <ErrorBanner error={decide.error} />
      <Card className="overflow-hidden">
        {items.length ? (
          <ul className="divide-y divide-border">
            {items.map((i) => (
              <Row key={i.id} i={i} open={open} selected={selected.has(i.id)} onToggle={() => toggle(i.id)} onDecide={(d) => decide.mutate([{ id: i.id, decision: d }])} busy={decide.isPending} />
            ))}
          </ul>
        ) : (
          <EmptyState title="Nothing for you here" description="Items assigned to you show up here." />
        )}
      </Card>
      <ConfirmAction
        open={closing}
        onOpenChange={setClosing}
        title={`Close “${r.name}”?`}
        effects={[
          `Access marked “revoke” is removed now (${items.filter((i) => i.decision === "revoke").length}).`,
          `${r.progress.total - r.progress.decided} undecided: ${r.on_no_decision === "keep" ? "kept" : "revoked"}.`,
          "The review is then read-only; export the CSV as evidence.",
        ]}
        confirmLabel="Close and apply"
        askReason={false}
        onConfirm={close}
      />
    </>
  );
}

function Row({ i, open, selected, onToggle, onDecide, busy }: { i: Item; open: boolean; selected: boolean; onToggle: () => void; onDecide: (d: "keep" | "revoke") => void; busy: boolean }) {
  return (
    <li className={cn("flex flex-wrap items-center gap-3 px-4 py-3 text-[13px]", selected && "bg-primary-soft/40")}>
      {open && i.you_can_decide ? <input type="checkbox" checked={selected} onChange={onToggle} aria-label={`Select ${i.user.email}`} /> : <span className="w-[13px]" />}
      <div className="min-w-0 flex-1">
        <p className="font-medium">
          {i.user.name} <span className="font-normal text-fg-muted">{i.user.email}</span>
        </p>
        <p className="text-xs text-fg-muted">
          {i.access}
          {i.user.title ? ` · ${i.user.title}` : ""}
          {i.user.department ? ` · ${i.user.department}` : ""} · {i.user.last_login_at ? `last signed in ${timeAgo(i.user.last_login_at)}` : "never signed in"}
          {i.reviewer ? ` · reviewer ${i.reviewer}` : ""}
        </p>
        {i.decided_by ? (
          <p className="text-xs text-fg-subtle">
            {i.decision === "keep" ? "Kept" : "Revoked"} by {i.decided_by}
            {i.note ? `: “${i.note}”` : ""}
            {i.outcome ? ` · ${i.outcome.replace("_", " ")}` : ""}
          </p>
        ) : i.outcome ? (
          <p className="text-xs text-fg-subtle">Undecided · {i.outcome.replace("_", " ")}</p>
        ) : null}
      </div>
      {open && i.you_can_decide ? (
        <div className="flex gap-1.5">
          <Button size="sm" variant={i.decision === "keep" ? "primary" : "secondary"} disabled={busy} onClick={() => onDecide("keep")}>
            <Check /> Keep
          </Button>
          <Button size="sm" variant={i.decision === "revoke" ? "danger" : "danger-outline"} disabled={busy} onClick={() => onDecide("revoke")}>
            <X /> Revoke
          </Button>
        </div>
      ) : i.decision ? (
        <StatusPill tone={i.decision === "keep" ? "success" : "danger"}>{i.decision === "keep" ? "Keep" : "Revoke"}</StatusPill>
      ) : null}
    </li>
  );
}
