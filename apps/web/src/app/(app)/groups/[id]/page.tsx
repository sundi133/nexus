"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, Trash2, UserPlus, X } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/features/confirm-action";
import { MfaBadge, UserStatusPill } from "@/components/features/user-bits";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Avatar, Card, EmptyState, ErrorBanner, PageHeader, Skeleton } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { qk, useCan } from "@/lib/queries";

export default function GroupPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const qc = useQueryClient();
  const can = useCan();
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const group = useQuery({ queryKey: qk.group(id), queryFn: () => unwrap(api.GET("/v1/groups/{id}", { params: { path: { id } } })) });
  const members = useQuery({
    queryKey: qk.groupMembers(id),
    queryFn: () => unwrap(api.GET("/v1/groups/{id}/members", { params: { path: { id }, query: { limit: 200 } } })),
  });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["group", id] });
    qc.invalidateQueries({ queryKey: ["groups"] });
  };
  const remove = useMutation({
    mutationFn: (userId: string) => unwrap(api.DELETE("/v1/groups/{id}/members/{userId}", { params: { path: { id, userId } } })),
    onSuccess: () => {
      refresh();
      toast.success("Removed from group");
    },
  });

  if (group.isPending) return <Skeleton className="h-32" />;
  if (!group.data) return <ErrorBanner error={group.error} />;
  const g = group.data;

  return (
    <>
      <Link href="/groups" className="mb-3 inline-flex items-center gap-1 text-[13px] text-fg-muted hover:text-fg">
        <ChevronLeft className="size-4" /> Groups
      </Link>
      <PageHeader
        title={g.name}
        description={g.description || `${g.member_count} members`}
        actions={
          can("groups:write") ? (
            <>
              <Button onClick={() => setDeleting(true)} variant="danger-outline">
                <Trash2 /> Delete
              </Button>
              <Button variant="primary" onClick={() => setAdding(true)}>
                <UserPlus /> Add members
              </Button>
            </>
          ) : null
        }
      />
      <Card className="overflow-hidden">
        {!members.data?.data.length ? (
          <EmptyState title="No members yet" description="Add people to this group to manage their access together." />
        ) : (
          <Table>
            <THead>
              <tr>
                <TH>Name</TH>
                <TH>Status</TH>
                <TH>MFA</TH>
                <TH />
              </tr>
            </THead>
            <tbody>
              {members.data.data.map((u) => (
                <TR key={u.id}>
                  <TD>
                    <Link href={`/users/${u.id}`} className="flex items-center gap-2.5">
                      <Avatar name={u.display_name} />
                      <span>
                        <span className="block font-medium">{u.display_name}</span>
                        <span className="block text-xs text-fg-muted">{u.email}</span>
                      </span>
                    </Link>
                  </TD>
                  <TD>
                    <UserStatusPill status={u.status} />
                  </TD>
                  <TD>
                    <MfaBadge enrolled={u.mfa_enrolled} />
                  </TD>
                  <TD className="text-right">
                    {can("groups:write") ? (
                      <Button size="sm" variant="ghost" onClick={() => remove.mutate(u.id)} aria-label={`Remove ${u.display_name}`}>
                        <X /> Remove
                      </Button>
                    ) : null}
                  </TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <AddMembersDialog groupId={id} open={adding} onOpenChange={setAdding} existing={new Set(members.data?.data.map((m) => m.id))} onAdded={refresh} />
      <ConfirmAction
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete group "${g.name}"?`}
        effects={[`Remove ${g.member_count} membership(s)`, "Users themselves are not affected"]}
        confirmLabel="Delete group"
        danger
        askReason={false}
        onConfirm={async () => {
          await unwrap(api.DELETE("/v1/groups/{id}", { params: { path: { id } } }));
          qc.invalidateQueries({ queryKey: ["groups"] });
          toast.success("Group deleted");
          router.push("/groups");
        }}
      />
    </>
  );
}

function AddMembersDialog({ groupId, open, onOpenChange, existing, onAdded }: { groupId: string; open: boolean; onOpenChange: (v: boolean) => void; existing: Set<string>; onAdded: () => void }) {
  const [q, setQ] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const users = useQuery({
    queryKey: ["users", { q, pick: groupId }],
    queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { q: q || undefined, limit: 20 } } })),
    enabled: open,
  });
  const add = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/groups/{id}/members", { params: { path: { id: groupId } }, body: { user_ids: [...picked] } })),
    onSuccess: () => {
      onAdded();
      toast.success(`Added ${picked.size} member(s)`);
      setPicked(new Set());
      onOpenChange(false);
    },
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="Add members">
        <Input autoFocus placeholder="Search people" value={q} onChange={(e) => setQ(e.target.value)} />
        <ul className="mt-3 max-h-72 divide-y divide-border overflow-y-auto rounded-md border border-border">
          {users.data?.data
            .filter((u) => !existing.has(u.id))
            .map((u) => (
              <li key={u.id}>
                <label className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-bg-subtle">
                  <input
                    type="checkbox"
                    checked={picked.has(u.id)}
                    onChange={() => {
                      const next = new Set(picked);
                      if (next.has(u.id)) next.delete(u.id);
                      else next.add(u.id);
                      setPicked(next);
                    }}
                  />
                  <Avatar name={u.display_name} size={24} />
                  <span className="text-[13px]">
                    {u.display_name} <span className="text-fg-subtle">{u.email}</span>
                  </span>
                </label>
              </li>
            ))}
        </ul>
        <div className="mt-4 flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" disabled={!picked.size} loading={add.isPending} onClick={() => add.mutate()}>
            Add {picked.size || ""}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
