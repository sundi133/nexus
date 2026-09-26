"use client";

import type { Schemas } from "@nexus/api-client";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Laptop, Plus, Search, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { toast } from "sonner";
import { checkTitle, ComplianceBadge, OnlineDot, PLATFORM_LABEL, PlatformIcon } from "@/components/features/device-bits";
import { EnrollInstructions } from "@/components/features/enroll-instructions";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent, Tabs, TabsContent, TabsList } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, fieldErrors, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime, timeAgo } from "@/lib/utils";

function DevicesView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const can = useCan();
  const [q, setQ] = useState(params.get("q") ?? "");
  const [adding, setAdding] = useState(false);
  const filters = {
    q: params.get("q") ?? undefined,
    compliance: (params.get("compliance") as Schemas["Device"]["compliance"]) ?? undefined,
    platform: (params.get("platform") as Schemas["Device"]["platform"]) ?? undefined,
  };
  const setParam = (k: string, v: string | undefined) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    router.replace(`${pathname}?${next}`);
  };
  useEffect(() => {
    const t = setTimeout(() => (params.get("q") ?? "") !== q && setParam("q", q || undefined), 250);
    return () => clearTimeout(t);
  }, [q]); // eslint-disable-line react-hooks/exhaustive-deps

  const devices = useInfiniteQuery({
    queryKey: ["devices", filters],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => unwrap(api.GET("/v1/devices", { params: { query: { ...filters, cursor: pageParam, limit: 50 } } })),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    refetchInterval: 30_000,
  });
  const rows = devices.data?.pages.flatMap((p) => p.data) ?? [];
  const filtered = !!(filters.q || filters.compliance || filters.platform);

  return (
    <>
      <PageHeader
        title="Devices"
        description="Laptops and desktops running the Nexus agent, and whether they meet your device policies."
        actions={
          can("devices:write") ? (
            <Button variant="primary" onClick={() => setAdding(true)}>
              <Plus /> Add devices
            </Button>
          ) : null
        }
      />
      <Tabs defaultValue="devices">
        <TabsList tabs={[{ value: "devices", label: "Devices" }, { value: "enrollment", label: "Enrollment tokens" }]} />
        <TabsContent value="devices">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <div className="relative w-full max-w-xs">
              <Search className="pointer-events-none absolute left-2.5 top-2 size-4 text-fg-subtle" />
              <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Hostname, serial or user" className="pl-8" aria-label="Search devices" />
            </div>
            <Select value={filters.compliance ?? ""} onChange={(e) => setParam("compliance", e.target.value || undefined)} aria-label="Compliance">
              <option value="">Any compliance</option>
              <option value="compliant">Compliant</option>
              <option value="non_compliant">Not compliant</option>
              <option value="unknown">Unknown</option>
            </Select>
            <Select value={filters.platform ?? ""} onChange={(e) => setParam("platform", e.target.value || undefined)} aria-label="Platform">
              <option value="">Any platform</option>
              <option value="macos">macOS</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </Select>
            {filtered ? (
              <Button variant="ghost" size="sm" onClick={() => router.replace(pathname)}>
                <X /> Clear
              </Button>
            ) : null}
          </div>
          <Card className="overflow-hidden">
            {devices.isPending ? (
              <Skeleton className="m-4 h-24" />
            ) : rows.length === 0 ? (
              <EmptyState
                icon={<Laptop />}
                title={filtered ? "No devices match these filters" : "No devices yet"}
                description={filtered ? "Try clearing a filter." : "Install the Nexus agent to see each computer's security posture here."}
                action={!filtered && can("devices:write") ? <Button onClick={() => setAdding(true)}>Add your first device</Button> : undefined}
              />
            ) : (
              <Table>
                <THead>
                  <tr>
                    <TH>Device</TH>
                    <TH>Compliance</TH>
                    <TH className="hidden md:table-cell">User</TH>
                    <TH className="hidden lg:table-cell">OS</TH>
                    <TH className="text-right">Last seen</TH>
                  </tr>
                </THead>
                <tbody>
                  {rows.map((d) => (
                    <TR key={d.id} className="cursor-pointer" onClick={() => router.push(`/devices/${d.id}`)}>
                      <TD>
                        <Link href={`/devices/${d.id}`} className="flex items-center gap-2.5" onClick={(e) => e.stopPropagation()}>
                          <PlatformIcon platform={d.platform} />
                          <span className="min-w-0">
                            <span className="block truncate font-medium">{d.hostname}</span>
                            <span className="block truncate text-xs text-fg-muted">{d.model || PLATFORM_LABEL[d.platform]}</span>
                          </span>
                        </Link>
                      </TD>
                      <TD>
                        <ComplianceBadge compliance={d.compliance} graceUntil={d.compliance_grace_until} />
                        {d.failing_checks.length ? <p className="mt-0.5 text-xs text-fg-muted">{d.failing_checks.map(checkTitle).join(", ")}</p> : null}
                      </TD>
                      <TD className="hidden md:table-cell">{d.primary_user ? d.primary_user.display_name : <span className="text-fg-subtle">Unassigned</span>}</TD>
                      <TD className="hidden text-fg-muted lg:table-cell">
                        {PLATFORM_LABEL[d.platform]} {d.os_version}
                      </TD>
                      <TD className="text-right text-fg-muted">
                        <span className="inline-flex items-center gap-1.5">
                          <OnlineDot online={d.online} /> {d.online ? "Online" : timeAgo(d.last_seen_at)}
                        </span>
                      </TD>
                    </TR>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </TabsContent>
        <TabsContent value="enrollment">
          <EnrollmentTokens onCreate={() => setAdding(true)} />
        </TabsContent>
      </Tabs>
      <AddDevicesDialog open={adding} onOpenChange={setAdding} />
    </>
  );
}

function EnrollmentTokens({ onCreate }: { onCreate: () => void }) {
  const qc = useQueryClient();
  const can = useCan();
  const tokens = useQuery({ queryKey: ["enrollment-tokens"], queryFn: () => unwrap(api.GET("/v1/devices/enrollment-tokens")) });
  const revoke = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/v1/devices/enrollment-tokens/{id}", { params: { path: { id } } })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["enrollment-tokens"] });
      toast.success("Token revoked. Devices already enrolled keep working.");
    },
  });
  return (
    <Card className="overflow-hidden">
      {!tokens.data?.data.length ? (
        <EmptyState title="No enrollment tokens" description="Create one to deploy the agent manually or through your MDM." action={can("devices:write") ? <Button onClick={onCreate}>Create a token</Button> : undefined} />
      ) : (
        <Table>
          <THead>
            <tr>
              <TH>Name</TH>
              <TH>Used</TH>
              <TH>Expires</TH>
              <TH />
            </tr>
          </THead>
          <tbody>
            {tokens.data.data.map((t) => (
              <TR key={t.id}>
                <TD className="font-medium">{t.name}</TD>
                <TD className="tabular">
                  {t.uses}
                  {t.max_uses ? ` / ${t.max_uses}` : ""}
                </TD>
                <TD className="text-fg-muted">{t.revoked ? <StatusPill>Inactive</StatusPill> : formatDateTime(t.expires_at)}</TD>
                <TD className="text-right">
                  {!t.revoked && can("devices:write") ? (
                    <Button size="sm" variant="ghost" onClick={() => revoke.mutate(t.id)}>
                      Revoke
                    </Button>
                  ) : null}
                </TD>
              </TR>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

function AddDevicesDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState({ name: "", days: "30", max: "" });
  const [install, setInstall] = useState<Schemas["EnrollmentInstructions"] | null>(null);
  const create = useMutation({
    mutationFn: () =>
      unwrap(api.POST("/v1/devices/enrollment-tokens", { body: { name: form.name, expires_in_days: Number(form.days), max_uses: form.max ? Number(form.max) : null } })),
    onSuccess: (r) => {
      setInstall(r);
      qc.invalidateQueries({ queryKey: ["enrollment-tokens"] });
    },
    onError: () => {},
  });
  const close = (v: boolean) => {
    if (!v) {
      setInstall(null);
      setForm({ name: "", days: "30", max: "" });
    }
    onOpenChange(v);
  };
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent title={install ? "Install the Nexus agent" : "Add devices"} description={install ? undefined : "Create an enrollment token, then run one command on each computer (or push it with your MDM)."} className="max-w-lg">
        {install ? (
          <EnrollInstructions install={install} />
        ) : (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            {!Object.keys(fieldErrors(create.error)).length ? <ErrorBanner error={create.error} /> : null}
            <Field label="Token name" htmlFor="tok-name" hint="For your records, e.g. “Engineering laptops” or “Jamf rollout”.">
              <Input id="tok-name" autoFocus required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Expires after" htmlFor="tok-days">
                <Select id="tok-days" value={form.days} onChange={(e) => setForm({ ...form, days: e.target.value })} className="w-full">
                  <option value="1">1 day</option>
                  <option value="7">7 days</option>
                  <option value="30">30 days</option>
                  <option value="90">90 days</option>
                </Select>
              </Field>
              <Field label="Max devices" htmlFor="tok-max" hint="Blank = unlimited">
                <Input id="tok-max" type="number" min={1} value={form.max} onChange={(e) => setForm({ ...form, max: e.target.value })} />
              </Field>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" loading={create.isPending}>
                Create token
              </Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

export default function DevicesPage() {
  return (
    <Suspense>
      <DevicesView />
    </Suspense>
  );
}
