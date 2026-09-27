"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Sparkles, UsersRound } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { toast } from "sonner";
import { emptyRule, type GroupRule, RuleBuilder, ruleComplete } from "@/components/features/group-rule";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, fieldErrors, unwrap } from "@/lib/api";
import { qk, useCan } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

function GroupsView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const can = useCan();
  const qc = useQueryClient();
  const groups = useQuery({ queryKey: qk.groups(), queryFn: () => unwrap(api.GET("/v1/groups", { params: { query: { limit: 200 } } })) });
  const [form, setForm] = useState({ name: "", description: "" });
  const [rule, setRule] = useState<GroupRule | null>(null);
  const open = params.get("new") === "1";
  const setOpen = (v: boolean) => router.replace(v ? `${pathname}?new=1` : pathname);

  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/groups", { body: { ...form, rule } })),
    onSuccess: (g) => {
      qc.invalidateQueries({ queryKey: ["groups"] });
      qc.invalidateQueries({ queryKey: qk.overview });
      toast.success(`Group "${g.name}" created`);
      setForm({ name: "", description: "" });
      setRule(null);
      router.push(`/groups/${g.id}`);
    },
    onError: () => {},
  });

  return (
    <>
      <PageHeader
        title="Groups"
        description="Groups drive app access, device policies and, soon, agent tool permissions."
        actions={
          can("groups:write") ? (
            <Button variant="primary" onClick={() => setOpen(true)}>
              <Plus /> New group
            </Button>
          ) : null
        }
      />
      <Card className="overflow-hidden">
        {groups.isPending ? (
          <div className="space-y-2 p-4">
            <Skeleton className="h-9" />
            <Skeleton className="h-9" />
          </div>
        ) : !groups.data?.data.length ? (
          <EmptyState
            icon={<UsersRound />}
            title="No groups yet"
            description="Create groups like Engineering or Contractors to manage access in bulk."
            action={can("groups:write") ? <Button onClick={() => setOpen(true)}>Create a group</Button> : undefined}
          />
        ) : (
          <Table>
            <THead>
              <tr>
                <TH>Name</TH>
                <TH>Members</TH>
                <TH className="text-right">Updated</TH>
              </tr>
            </THead>
            <tbody>
              {groups.data.data.map((g) => (
                <TR key={g.id} className="cursor-pointer" onClick={() => router.push(`/groups/${g.id}`)}>
                  <TD>
                    <Link href={`/groups/${g.id}`} className="font-medium" onClick={(e) => e.stopPropagation()}>
                      {g.name}
                    </Link>
                    {g.rule ? (
                      <span className="ml-2 align-middle">
                        <StatusPill tone="primary" dot={false}>
                          <Sparkles className="size-3" /> Dynamic
                        </StatusPill>
                      </span>
                    ) : g.managed_by ? (
                      <span className="ml-2 align-middle">
                        <StatusPill dot={false}>From {g.managed_by}</StatusPill>
                      </span>
                    ) : null}
                    {g.description ? <p className="text-xs text-fg-muted">{g.description}</p> : null}
                  </TD>
                  <TD className="tabular">{g.member_count}</TD>
                  <TD className="text-right text-fg-muted">{timeAgo(g.updated_at)}</TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent title="New group" className={rule ? "max-w-2xl" : undefined}>
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            {!Object.keys(fieldErrors(create.error)).length ? <ErrorBanner error={create.error} /> : null}
            <Field label="Name" htmlFor="g-name" error={fieldErrors(create.error).name}>
              <Input id="g-name" autoFocus required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Engineering" />
            </Field>
            <Field label="Description" htmlFor="g-desc">
              <Input id="g-desc" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </Field>
            <fieldset className="space-y-2">
              <legend className="mb-1.5 text-[13px] font-medium">Members</legend>
              <label className="flex items-center gap-2 text-[13px]">
                <input type="radio" name="g-kind" checked={!rule} onChange={() => setRule(null)} /> Chosen by hand
              </label>
              <label className="flex items-center gap-2 text-[13px]">
                <input type="radio" name="g-kind" checked={!!rule} onChange={() => setRule(emptyRule())} /> Everyone who matches a rule (dynamic)
              </label>
            </fieldset>
            {rule ? <RuleBuilder rule={rule} onChange={setRule} /> : null}
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" loading={create.isPending} disabled={!!rule && !ruleComplete(rule)}>
                Create group
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default function GroupsPage() {
  return (
    <Suspense>
      <GroupsView />
    </Suspense>
  );
}
