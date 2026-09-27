"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/features/confirm-action";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, Skeleton } from "@/components/ui/misc";
import { api, ApiProblem, unwrap } from "@/lib/api";
import { qk, useCan, useMe } from "@/lib/queries";

/** Downloads an API file through the BFF (a fetch, so a step-up prompt can retry it). */
async function download(path: string, fallbackName: string) {
  const res = await fetch(`/bff${path}`, { headers: { "x-nexus-csrf": "1" } });
  if (!res.ok) throw new ApiProblem(res.status, await res.json());
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await res.blob());
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

const longDate = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: "long" });

/** Settings → Organization: export everything, what's kept for how long, and deleting the organization. */
export function OrgDataCard() {
  const can = useCan();
  const me = useMe();
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const isOwner = !!me.data?.roles.includes("owner");
  const retention = useQuery({ queryKey: ["data-retention"], queryFn: () => unwrap(api.GET("/v1/org/data-retention")), enabled: can("org:manage") });
  const deletion = useQuery({ queryKey: ["org-deletion"], queryFn: () => unwrap(api.GET("/v1/org/deletion")), enabled: can("org:manage") });
  const [confirmDelete, setConfirmDelete] = useState(false);
  const exporting = useMutation({
    mutationFn: () => withStepUp(() => download("/v1/org/export", "nexus-export.ndjson.gz")),
    onSuccess: () => toast.success("Export downloaded"),
    onError: (e) => toast.error(e instanceof Error ? e.message : "Export failed"),
  });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["org-deletion"] });
    qc.invalidateQueries({ queryKey: qk.me });
  };
  const cancel = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.DELETE("/v1/org/deletion"))),
    onSuccess: () => {
      refresh();
      toast.success("Deletion cancelled");
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Couldn't cancel"),
  });
  if (!can("org:manage") && !can("data:export")) return null;
  const orgName = me.data?.organization.name ?? "";
  const scheduled = deletion.data?.scheduled_for;

  return (
    <Card id="data" className="overflow-hidden">
      <CardHeader
        title="Data and privacy"
        description="Take all your data with you, see what's kept and for how long, or delete the organization."
        actions={
          can("data:export") ? (
            <Button size="sm" onClick={() => exporting.mutate()} loading={exporting.isPending}>
              <Download className="size-3.5" /> Export all data
            </Button>
          ) : null
        }
      />
      <p className="px-4 pb-3 text-xs text-fg-muted">
        The export is every table as gzipped JSON lines from one consistent snapshot, without secrets (password hashes, keys and credentials are left out and listed). It&apos;s recorded in the audit log.
      </p>

      {retention.data ? (
        <div className="border-t border-border">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-xs text-fg-muted">
                <th className="px-4 py-2 font-medium">Data</th>
                <th className="px-4 py-2 font-medium">Kept</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {retention.data.classes.map((r) => (
                <tr key={r.key}>
                  <td className="px-4 py-2 align-top">
                    {r.name}
                    {r.notes ? <span className="block text-xs text-fg-muted">{r.notes}</span> : null}
                  </td>
                  <td className="px-4 py-2 align-top text-fg-muted">{r.key === "audit_events" ? `${retention.data.audit_retention_days} days (your setting above)` : r.kept}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : can("org:manage") ? (
        <Skeleton className="m-4 h-24" />
      ) : null}

      {can("org:manage") ? (
        <div className="border-t border-danger/30 bg-danger-soft/40 px-4 py-3">
          {deletion.isPending ? null : scheduled ? (
            <div className="flex flex-wrap items-center justify-between gap-3 text-[13px]">
              <p>
                <strong className="text-danger">
                  {orgName} and all its data will be deleted on {longDate(scheduled)}.
                </strong>{" "}
                <span className="text-fg-muted">
                  Scheduled by {deletion.data?.requested_by ?? "an owner"}
                  {deletion.data?.reason ? `: “${deletion.data.reason}”` : ""}. Owners get a deletion certificate by email afterwards.
                </span>
              </p>
              {isOwner ? (
                <Button size="sm" onClick={() => cancel.mutate()} loading={cancel.isPending}>
                  Cancel deletion
                </Button>
              ) : null}
            </div>
          ) : (
            <div className="flex flex-wrap items-center justify-between gap-3 text-[13px]">
              <p>
                <span className="font-medium">Delete this organization</span>
                <span className="block text-xs text-fg-muted">
                  Everything is deleted {deletion.data?.grace_days ?? 30} days after you ask: people, devices, apps, policies and the audit log. Until then any owner can cancel.
                  {isOwner ? "" : " Only owners can do this."}
                </span>
              </p>
              {isOwner ? (
                <Button size="sm" variant="danger-outline" onClick={() => setConfirmDelete(true)}>
                  <Trash2 className="size-3.5" /> Delete organization…
                </Button>
              ) : null}
            </div>
          )}
        </div>
      ) : null}

      <ConfirmAction
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        danger
        title={`Delete ${orgName}?`}
        effects={[
          `Delete every person, group, app, device, policy and audit event in ${deletion.data?.grace_days ?? 30} days`,
          "Stop sign-ins to every app that uses Nexus, and disconnect every device",
          "Tell owners and admins now; any owner can cancel until then",
          "Export your data first if you want to keep it",
        ]}
        confirmLabel="Schedule deletion"
        reasonPlaceholder="e.g. Moving to another provider"
        typeToConfirm={orgName}
        onConfirm={(reason) =>
          withStepUp(() => unwrap(api.POST("/v1/org/deletion", { body: { confirm_name: orgName, reason: reason || "No reason given" } }))).then(() => {
            refresh();
            toast.success("Deletion scheduled");
          })
        }
      />
    </Card>
  );
}

/** A person's page: download everything about them, or erase them (privacy requests). */
export function PersonDataActions({ user }: { user: { id: string; email: string; status: string; break_glass?: boolean } }) {
  const can = useCan();
  const router = useRouter();
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [confirmErase, setConfirmErase] = useState(false);
  const exporting = useMutation({
    mutationFn: () => withStepUp(() => download(`/v1/users/${user.id}/data-export`, `person-${user.id}.json`)),
    onError: (e) => toast.error(e instanceof Error ? e.message : "Export failed"),
  });
  const erasable = user.status === "suspended" || user.status === "deprovisioned";
  return (
    <>
      {can("users:read") ? (
        <Button size="sm" onClick={() => exporting.mutate()} loading={exporting.isPending} title="Everything Nexus holds about this person (privacy access request)">
          <Download className="size-3.5" /> Download data
        </Button>
      ) : null}
      {can("users:erase") && !user.break_glass ? (
        <Button
          size="sm"
          variant="danger-outline"
          disabled={!erasable}
          title={erasable ? "Permanently delete this person and their personal data" : "Suspend or offboard them first"}
          onClick={() => setConfirmErase(true)}
        >
          <Trash2 className="size-3.5" /> Erase…
        </Button>
      ) : null}
      <ConfirmAction
        open={confirmErase}
        onOpenChange={setConfirmErase}
        danger
        title={`Erase ${user.email}?`}
        effects={[
          "Permanently delete their profile, group and role memberships, MFA factors, sessions, requests and notifications",
          "Keep the organization's records (devices, policies they created, decisions they made) without them",
          "Keep audit events about them until audit retention removes them: the log can't be edited",
          "This can't be undone",
        ]}
        confirmLabel="Erase permanently"
        reasonPlaceholder="e.g. Erasure request PRIV-1042"
        typeToConfirm={user.email}
        onConfirm={(reason) =>
          withStepUp(() => unwrap(api.POST("/v1/users/{id}/erase", { params: { path: { id: user.id } }, body: { confirm: user.email, reason: reason || "Erasure request" } }))).then(() => {
            qc.invalidateQueries({ queryKey: ["users"] });
            toast.success("Erased");
            router.push("/users");
          })
        }
      />
    </>
  );
}
