"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ClipboardCheck, Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, pluralize, timeAgo } from "@/lib/utils";

type Review = Schemas["AccessReview"];

export default function AccessReviewsPage() {
  const list = useQuery({ queryKey: ["access-reviews"], queryFn: () => unwrap(api.GET("/v1/access-reviews")) });
  const can = useCan();
  const [starting, setStarting] = useState(false);
  return (
    <>
      <PageHeader
        title="Access reviews"
        description="Check who still needs access: reviewers keep or revoke each person's access to an app, a group or an admin role, and Nexus applies it when the review closes."
        actions={
          can("access:manage") ? (
            <Button variant="primary" onClick={() => setStarting(true)}>
              <Plus /> Start a review
            </Button>
          ) : null
        }
      />
      {list.isPending ? (
        <Skeleton className="h-40" />
      ) : !list.data?.data.length ? (
        <Card>
          <EmptyState icon={<ClipboardCheck />} title="No reviews yet" description="Auditors ask for periodic access reviews (SOC 2, ISO 27001). Start one for an app, a group or your admin roles." />
        </Card>
      ) : (
        <div className="space-y-3">
          {list.data.data.map((r) => (
            <ReviewRow key={r.id} r={r} />
          ))}
        </div>
      )}
      {starting ? <StartDialog onClose={() => setStarting(false)} /> : null}
    </>
  );
}

function ReviewRow({ r }: { r: Review }) {
  const pct = r.progress.total ? Math.round((r.progress.decided / r.progress.total) * 100) : 0;
  const overdue = r.status === "open" && new Date(r.due_at) < new Date();
  return (
    <Link href={`/access-reviews/${r.id}`} className="block">
      <Card className="p-4 transition-colors hover:bg-bg-subtle">
        <div className="flex flex-wrap items-center gap-3">
          <div className="min-w-0 flex-1">
            <p className="flex flex-wrap items-center gap-2 text-[13px] font-semibold">
              {r.name}
              {r.status === "closed" ? <StatusPill>Closed</StatusPill> : overdue ? <StatusPill tone="warning">Closing</StatusPill> : <StatusPill tone="primary">Open</StatusPill>}
              {r.progress.yours_to_decide ? <StatusPill tone="warning">{r.progress.yours_to_decide} for you</StatusPill> : null}
            </p>
            <p className="text-xs text-fg-muted">
              <span className="capitalize">{r.scope.name}</span> · reviewed by {r.reviewers.kind === "manager" ? "managers" : "chosen reviewers"} · {r.status === "closed" ? `closed ${timeAgo(r.closed_at!)}` : `due ${new Date(r.due_at).toLocaleDateString()}`}
            </p>
          </div>
          <div className="w-44">
            <div className="h-1.5 overflow-hidden rounded-full bg-bg-muted">
              <div className={cn("h-full rounded-full", r.status === "closed" ? "bg-fg-subtle" : "bg-primary")} style={{ width: `${pct}%` }} />
            </div>
            <p className="mt-1 text-right text-xs text-fg-muted">
              {r.status === "closed" ? `${r.summary.kept ?? 0} kept · ${r.summary.revoked ?? 0} revoked` : `${r.progress.decided} of ${r.progress.total} decided`}
            </p>
          </div>
        </div>
      </Card>
    </Link>
  );
}

function StartDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const router = useRouter();
  const withStepUp = useStepUp();
  const users = useQuery({ queryKey: ["users", "all-for-picker"], queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { limit: 200 } } })) });
  const groups = useQuery({ queryKey: ["groups", "all-for-picker"], queryFn: () => unwrap(api.GET("/v1/groups", { params: { query: { limit: 200 } } })) });
  const apps = useQuery({ queryKey: ["apps", "all-for-picker"], queryFn: () => unwrap(api.GET("/v1/apps")) });
  const [scope, setScope] = useState<"app" | "group" | "admin_roles">("app");
  const [target, setTarget] = useState("");
  const [name, setName] = useState(`Access review ${new Date().toLocaleDateString(undefined, { month: "short", year: "numeric" })}`);
  const [kind, setKind] = useState<"users" | "manager">("manager");
  const [reviewer, setReviewer] = useState("");
  const [days, setDays] = useState(14);
  const [fallback, setFallback] = useState<"keep" | "revoke">("keep");
  const start = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.POST("/v1/access-reviews", {
            body: {
              name: name.trim(),
              scope: scope === "admin_roles" ? { type: scope } : { type: scope, id: target },
              reviewers: kind === "users" ? { kind, ids: [reviewer] } : { kind, fallback_ids: [reviewer] },
              due_in_days: days,
              on_no_decision: fallback,
            },
          }),
        ),
      ),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["access-reviews"] });
      toast.success(`Review started: ${pluralize(r.progress.total, "person")} to check`);
      router.push(`/access-reviews/${r.id}`);
    },
  });
  const ready = !!name.trim() && !!reviewer && (scope === "admin_roles" || !!target);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Start an access review" description="Nexus takes a snapshot of who has the access now and asks the reviewers about each person." className="max-w-lg">
        <div className="space-y-4">
          <Field label="Name" htmlFor="r-name">
            <Input id="r-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={200} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Review who has" htmlFor="r-scope">
              <Select id="r-scope" className="w-full" value={scope} onChange={(e) => (setScope(e.target.value as typeof scope), setTarget(""))}>
                <option value="app">An app</option>
                <option value="group">A group</option>
                <option value="admin_roles">Admin roles</option>
              </Select>
            </Field>
            {scope !== "admin_roles" ? (
              <Field label={scope === "app" ? "App" : "Group"} htmlFor="r-target">
                <Select id="r-target" className="w-full" value={target} onChange={(e) => setTarget(e.target.value)}>
                  <option value="">Choose…</option>
                  {(scope === "app" ? (apps.data?.data ?? []) : (groups.data?.data ?? [])).map((x) => (
                    <option key={x.id} value={x.id}>
                      {x.name}
                    </option>
                  ))}
                </Select>
              </Field>
            ) : null}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Reviewed by" htmlFor="r-kind">
              <Select id="r-kind" className="w-full" value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
                <option value="manager">Each person's manager</option>
                <option value="users">A reviewer</option>
              </Select>
            </Field>
            <Field label={kind === "manager" ? "…or, without a manager" : "Reviewer"} htmlFor="r-reviewer">
              <Select id="r-reviewer" className="w-full" value={reviewer} onChange={(e) => setReviewer(e.target.value)}>
                <option value="">Choose…</option>
                {(users.data?.data ?? [])
                  .filter((u) => u.status === "active")
                  .map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.email}
                    </option>
                  ))}
              </Select>
            </Field>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Due in" htmlFor="r-days">
              <Select id="r-days" className="w-full" value={String(days)} onChange={(e) => setDays(Number(e.target.value))}>
                {[3, 7, 14, 30].map((d) => (
                  <option key={d} value={d}>
                    {d} days
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="If nobody decides" htmlFor="r-fallback">
              <Select id="r-fallback" className="w-full" value={fallback} onChange={(e) => setFallback(e.target.value as typeof fallback)}>
                <option value="keep">Keep their access</option>
                <option value="revoke">Revoke it</option>
              </Select>
            </Field>
          </div>
          <p className="text-xs text-fg-muted">Nobody reviews their own access, break-glass accounts are left out, and the last owner is never removed.</p>
          <ErrorBanner error={start.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={start.isPending} disabled={!ready} onClick={() => start.mutate()}>
              Start review
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
