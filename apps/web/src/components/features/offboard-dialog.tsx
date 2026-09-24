"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, UserMinus } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { ErrorBanner, Skeleton } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { formatDateTime, pluralize } from "@/lib/utils";

export const offboardingKey = (id: string) => ["offboarding", id];

export function useOffboarding(userId: string, enabled: boolean) {
  return useQuery({ queryKey: offboardingKey(userId), queryFn: () => unwrap(api.GET("/v1/users/{id}/offboarding", { params: { path: { id: userId } } })), enabled });
}

/** DIR-06: shows exactly what will be removed, then does it now or on a date. */
export function OffboardDialog({ userId, onClose, onDone }: { userId: string; onClose: () => void; onDone: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const preview = useOffboarding(userId, true);
  const [when, setWhen] = useState<"now" | "later">("now");
  const [date, setDate] = useState("");
  const [reason, setReason] = useState("");
  const p = preview.data;
  const at = when === "later" && date ? new Date(`${date}T17:00:00`).toISOString() : undefined;

  const go = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/users/{id}/offboard", { params: { path: { id: userId } }, body: { reason, ...(at ? { at } : {}) } }))),
    onSuccess: (r) => {
      qc.setQueryData(offboardingKey(userId), r);
      toast.success(at ? `Offboarding scheduled for ${formatDateTime(at)}` : `${r.user.display_name} was offboarded`, {
        description: at ? "Nothing changes until then. You can cancel it on their profile." : "Their access is gone; app accounts are being deactivated.",
      });
      onDone();
      onClose();
    },
  });

  const items = p
    ? [
        "Deprovision the account and sign them out everywhere" + (p.sessions ? ` (${pluralize(p.sessions, "session")})` : ""),
        p.admin_roles.length ? `Remove admin roles: ${p.admin_roles.join(", ")}` : null,
        p.groups.length ? `Remove from ${pluralize(p.groups.length, "group")}: ${p.groups.map((g) => g.name).join(", ")}` : null,
        ...p.apps.filter((a) => a.provisioned).map((a) => `${a.action === "delete" ? "Delete" : "Deactivate"} their ${a.name} account`),
        p.apps.some((a) => !a.provisioned) ? `Remove sign-in to ${p.apps.filter((a) => !a.provisioned).map((a) => a.name).join(", ")} (no provisioning: their account inside the app stays)` : null,
        p.factors ? `Remove ${pluralize(p.factors, "MFA factor")}` : null,
        p.devices.length ? `Unassign ${p.devices.map((d) => d.hostname).join(", ")}, and remind IT to collect it` : null,
      ].filter((x): x is string => !!x)
    : [];

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={p ? `Offboard ${p.user.display_name}?` : "Offboard"} description="Everything they can access, removed in one step. This can't be undone." className="max-w-lg">
        {preview.isPending ? (
          <Skeleton className="h-40" />
        ) : !p ? (
          <ErrorBanner error={preview.error} />
        ) : (
          <div className="space-y-4 text-[13px]">
            <ul className="space-y-1.5 rounded-md border border-border bg-bg-subtle px-4 py-3">
              {items.map((i) => (
                <li key={i} className="flex gap-2">
                  <UserMinus className="mt-0.5 size-3.5 shrink-0 text-danger" /> {i}
                </li>
              ))}
            </ul>
            {p.user.managed_by_directory ? <p className="text-xs text-fg-muted">They're synced from your directory. Remove them there too, or the next sync will report them as still present.</p> : null}
            <fieldset className="space-y-1.5">
              <legend className="mb-1 font-medium">When</legend>
              <label className="flex items-center gap-2">
                <input type="radio" checked={when === "now"} onChange={() => setWhen("now")} /> Now
              </label>
              <label className="flex items-center gap-2">
                <input type="radio" checked={when === "later"} onChange={() => setWhen("later")} /> On their last day, at 5 pm
                {when === "later" ? <Input type="date" className="ml-2 w-44" value={date} min={new Date(Date.now() + 86400_000).toISOString().slice(0, 10)} onChange={(e) => setDate(e.target.value)} aria-label="Last day" /> : null}
              </label>
            </fieldset>
            <Field label="Reason (for the audit log)" htmlFor="ob-reason">
              <Input id="ob-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Resigned, contract ended…" maxLength={500} />
            </Field>
            <ErrorBanner error={go.error} />
            <div className="flex justify-end gap-2 border-t border-border pt-4">
              <Button variant="ghost" onClick={onClose}>
                Cancel
              </Button>
              <Button variant="danger" loading={go.isPending} disabled={when === "later" && !date} onClick={() => go.mutate()}>
                {when === "later" ? (
                  <>
                    <CalendarClock /> Schedule offboarding
                  </>
                ) : (
                  <>
                    <UserMinus /> Offboard now
                  </>
                )}
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
