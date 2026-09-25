"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, Trash2, UserRound } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useState } from "react";
import { toast } from "sonner";
import { ActivityList } from "@/components/features/activity";
import { ConfirmAction } from "@/components/features/confirm-action";
import { CheckList, ComplianceBadge, OnlineDot, PLATFORM_LABEL, PlatformIcon } from "@/components/features/device-bits";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Avatar, Card, CardHeader, EmptyState, ErrorBanner, KeyValue, Skeleton } from "@/components/ui/misc";
import { Dialog, DialogContent, Tabs, TabsContent, TabsList } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime, timeAgo } from "@/lib/utils";

const gb = (b: unknown) => (typeof b === "number" && b > 0 ? `${Math.round(b / 1024 ** 3)} GB` : "—");
const duration = (s: unknown) => (typeof s === "number" && s > 0 ? (s > 86_400 ? `${Math.floor(s / 86_400)} days` : `${Math.floor(s / 3600)} hours`) : "—");

export default function DevicePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const qc = useQueryClient();
  const router = useRouter();
  const can = useCan();
  const [removing, setRemoving] = useState(false);
  const [assigning, setAssigning] = useState(false);
  const device = useQuery({ queryKey: ["device", id], queryFn: () => unwrap(api.GET("/v1/devices/{id}", { params: { path: { id } } })), refetchInterval: 30_000 });
  const activity = useQuery({
    queryKey: ["audit", { subject_id: id }],
    queryFn: () => unwrap(api.GET("/v1/audit/events", { params: { query: { subject_id: id, limit: 50 } } })),
  });

  if (device.isPending) return <Skeleton className="h-40" />;
  if (!device.data) return <ErrorBanner error={device.error} />;
  const d = device.data;
  const inv = d.inventory as { cpu?: string; memory_bytes?: number; uptime_seconds?: number; console_user?: string; local_users?: { name: string; admin: boolean }[] };
  const failing = d.checks.filter((c) => c.status === "fail").length;

  return (
    <>
      <Link href="/devices" className="mb-3 inline-flex items-center gap-1 text-[13px] text-fg-muted hover:text-fg">
        <ChevronLeft className="size-4" /> Devices
      </Link>
      <div className="mb-5 flex flex-wrap items-start gap-4">
        <span className="flex size-12 items-center justify-center rounded-lg bg-bg-muted">
          <PlatformIcon platform={d.platform} className="size-6" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold tracking-tight">{d.hostname}</h1>
            <ComplianceBadge compliance={d.compliance} graceUntil={d.compliance_grace_until} />
          </div>
          <p className="mt-0.5 flex items-center gap-1.5 text-[13px] text-fg-muted">
            <OnlineDot online={d.online} /> {d.online ? "Online" : `Last seen ${timeAgo(d.last_seen_at)}`} · {d.model || PLATFORM_LABEL[d.platform]} · {PLATFORM_LABEL[d.platform]} {d.os_version}
          </p>
        </div>
        {can("devices:write") ? (
          <div className="flex gap-2">
            <Button onClick={() => setAssigning(true)}>
              <UserRound /> {d.primary_user ? "Change user" : "Assign user"}
            </Button>
            <Button variant="danger-outline" onClick={() => setRemoving(true)}>
              <Trash2 /> Remove
            </Button>
          </div>
        ) : null}
      </div>

      <Tabs defaultValue="compliance">
        <TabsList tabs={[{ value: "compliance", label: failing ? `Compliance (${failing} failing)` : "Compliance" }, { value: "details", label: "Details" }, { value: "activity", label: "Activity" }]} />
        <TabsContent value="compliance">
          <Card className="overflow-hidden">
            <CardHeader title="Policy checks" description={d.compliance_changed_at ? `Compliance last changed ${formatDateTime(d.compliance_changed_at)}` : "Evaluated on every check-in (about once a minute)."} />
            <CheckList checks={d.checks} />
          </Card>
        </TabsContent>
        <TabsContent value="details" className="grid gap-5 lg:grid-cols-2">
          <Card>
            <CardHeader title="Device" />
            <div className="p-4">
              <KeyValue
                items={[
                  ["Primary user", d.primary_user ? <Link key="u" href={`/users/${d.primary_user.id}`} className="hover:underline">{d.primary_user.display_name}</Link> : "Unassigned"],
                  ["Serial", <code key="s" className="font-mono text-xs">{d.serial || "—"}</code>],
                  ["OS", `${d.os_name || PLATFORM_LABEL[d.platform]} ${d.os_version} (${d.os_build || "—"})`],
                  ["Architecture", d.arch || "—"],
                  ["Agent", d.agent_version || "—"],
                  ["Enrolled", formatDateTime(d.enrolled_at)],
                  ["Last IP", <code key="ip" className="font-mono text-xs">{d.last_ip || "—"}</code>],
                ]}
              />
            </div>
          </Card>
          <Card>
            <CardHeader title="Hardware and users" />
            <div className="p-4">
              <KeyValue
                items={[
                  ["CPU", inv.cpu || "—"],
                  ["Memory", gb(inv.memory_bytes)],
                  ["Uptime", duration(inv.uptime_seconds)],
                  ["Signed-in user", inv.console_user || "—"],
                  ["Local admins", inv.local_users?.filter((u) => u.admin).map((u) => u.name).join(", ") || "—"],
                ]}
              />
            </div>
          </Card>
        </TabsContent>
        <TabsContent value="activity">
          <Card className="overflow-hidden">{activity.data?.data.length ? <ActivityList events={activity.data.data} /> : <EmptyState title="No activity yet" />}</Card>
        </TabsContent>
      </Tabs>

      <ConfirmAction
        open={removing}
        onOpenChange={setRemoving}
        title={`Remove ${d.hostname}?`}
        effects={["Its device key stops being accepted; the agent stops reporting and clears its enrollment", "It disappears from device lists (the audit history stays)", "To manage it again, enroll it with a new token"]}
        confirmLabel="Remove device"
        danger
        typeToConfirm={d.hostname}
        askReason={false}
        onConfirm={async () => {
          await unwrap(api.DELETE("/v1/devices/{id}", { params: { path: { id } } }));
          qc.invalidateQueries({ queryKey: ["devices"] });
          toast.success(`${d.hostname} removed`);
          router.push("/devices");
        }}
      />
      <AssignUserDialog deviceId={id} open={assigning} onOpenChange={setAssigning} />
    </>
  );
}

function AssignUserDialog({ deviceId, open, onOpenChange }: { deviceId: string; open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const users = useQuery({ queryKey: ["users", { q, assignDevice: true }], queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { q: q || undefined, limit: 15, status: "active" } } })), enabled: open });
  const save = useMutation({
    mutationFn: (userId: string | null) => unwrap(api.PATCH("/v1/devices/{id}", { params: { path: { id: deviceId } }, body: { primary_user_id: userId } })),
    onSuccess: (d) => {
      qc.setQueryData(["device", deviceId], d);
      qc.invalidateQueries({ queryKey: ["devices"] });
      toast.success(d.primary_user ? `Assigned to ${d.primary_user.display_name}` : "User unassigned");
      onOpenChange(false);
    },
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="Primary user" description="The person who uses this device. They'll see its compliance and get told what to fix.">
        <Input autoFocus placeholder="Search people" value={q} onChange={(e) => setQ(e.target.value)} />
        <ul className="mt-3 max-h-72 divide-y divide-border overflow-y-auto rounded-md border border-border">
          {users.data?.data.map((u) => (
            <li key={u.id}>
              <button className="flex w-full items-center gap-3 px-3 py-2 text-left text-[13px] hover:bg-bg-subtle" onClick={() => save.mutate(u.id)}>
                <Avatar name={u.display_name} size={24} /> {u.display_name} <span className="text-fg-subtle">{u.email}</span>
              </button>
            </li>
          ))}
        </ul>
        <div className="mt-3 flex justify-end">
          <Button variant="ghost" onClick={() => save.mutate(null)}>
            Unassign
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
