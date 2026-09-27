"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Cloud, KeyRound, Link2, ShieldBan, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { SaasLicenses } from "@/components/features/saas-licenses";
import { Dialog, DialogContent, SheetContent, Tabs, TabsContent, TabsList } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

const people = (n: number) => `${n} ${n === 1 ? "person" : "people"}`;

type SaasApp = Schemas["SaasApp"];
type Status = SaasApp["status"];

const STATUS: Record<Status, { tone: Tone; label: string }> = {
  unreviewed: { tone: "neutral", label: "Not reviewed" },
  approved: { tone: "success", label: "Approved" },
  unapproved: { tone: "danger", label: "Unapproved" },
};
const ACTION_LABEL = {
  allow: "Allowed, counted",
  warn: "Browsers warn",
  block: "Browsers block",
} as const;

/** SaaS management: which apps people use, which are approved, and what browsers do about the rest. */
export default function SaasPage() {
  const can = useCan();
  const [filter, setFilter] = useState<Status | "">("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [reviewing, setReviewing] = useState<SaasApp | null>(null);
  const list = useQuery({
    queryKey: ["saas-apps"],
    queryFn: () => unwrap(api.GET("/v1/saas/apps", { params: { query: { days: 30 } } })),
    refetchInterval: 60_000,
  });
  const s = list.data?.summary;
  const rows = (list.data?.data ?? []).filter((a) => (!filter || a.status === filter) && (!q || a.name.toLowerCase().includes(q.toLowerCase()) || a.category.toLowerCase().includes(q.toLowerCase())));

  return (
    <>
      <PageHeader
        title="SaaS apps"
        description="The work apps people use, found by the Nexus browser extension. Approve them, or warn about and block the ones you don't want company data in, and see which paid seats are used."
      />
      <Tabs defaultValue="apps">
        <TabsList
          tabs={[
            { value: "apps", label: "Apps in use" },
            { value: "licenses", label: "Licenses" },
          ]}
        />
        <TabsContent value="licenses">
          <SaasLicenses />
        </TabsContent>
        <TabsContent value="apps">
          <ErrorBanner error={list.error} />
          {list.isPending ? (
            <Skeleton className="h-40" />
          ) : (
            <>
              {can("devices:enforce") ? <DiscoveryCard on={!!s?.discovery} /> : null}
              <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
                <Tile label="Apps in use" value={s?.apps ?? 0} hint="last 30 days" />
                <Tile label="People" value={s?.people ?? 0} hint="using at least one" />
                <Tile label="Not reviewed" value={s?.unreviewed ?? 0} hint="in use, no decision yet" tone={s?.unreviewed ? "warning" : undefined} onClick={() => setFilter("unreviewed")} />
                <Tile label="Password sign-ins" value={s?.password_apps ?? 0} hint="apps on SSO that people still sign in to with a password" tone={s?.password_apps ? "warning" : undefined} />
              </div>
              <Card className="overflow-hidden">
                <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
                  <Input className="max-w-xs" placeholder="Search apps or categories" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search apps" />
                  <Select value={filter} onChange={(e) => setFilter(e.target.value as Status | "")} aria-label="Status">
                    <option value="">All statuses</option>
                    <option value="unreviewed">Not reviewed</option>
                    <option value="approved">Approved</option>
                    <option value="unapproved">Unapproved</option>
                  </Select>
                </div>
                {!rows.length ? (
                  <EmptyState
                    icon={<Cloud />}
                    title={s?.discovery ? "No apps found yet" : "Discovery is off"}
                    description={s?.discovery ? "Apps show up as people use them in browsers with the Nexus extension." : "Turn on SaaS discovery above to see which work apps people use."}
                  />
                ) : (
                  <Table>
                    <THead>
                      <TR>
                        <TH>App</TH>
                        <TH>People</TH>
                        <TH>Sign-in</TH>
                        <TH>Status</TH>
                        <TH>Last used</TH>
                        <TH />
                      </TR>
                    </THead>
                    <tbody>
                      {rows.map((a) => (
                        <TR key={a.key} className="cursor-pointer" onClick={() => setOpen(a.key)}>
                          <TD>
                            <p className="font-medium">{a.name}</p>
                            <p className="text-xs text-fg-muted">{a.category}</p>
                          </TD>
                          <TD>{a.people}</TD>
                          <TD>
                            {a.sso ? (
                              <span className="inline-flex items-center gap-1 text-xs">
                                <Link2 className="size-3.5 text-success" /> SSO
                                {a.password_people ? <span className="text-warning">· {people(a.password_people)} use a password</span> : null}
                              </span>
                            ) : a.password_people ? (
                              <span className="inline-flex items-center gap-1 text-xs text-fg-muted">
                                <KeyRound className="size-3.5" /> Password
                              </span>
                            ) : (
                              <span className="text-xs text-fg-subtle">—</span>
                            )}
                          </TD>
                          <TD>
                            <StatusPill tone={STATUS[a.status].tone}>{STATUS[a.status].label}</StatusPill>
                            {a.status === "unapproved" ? <span className="ml-2 text-xs text-fg-muted">{ACTION_LABEL[a.action]}</span> : null}
                          </TD>
                          <TD className="whitespace-nowrap text-fg-muted">{a.last_seen ? timeAgo(a.last_seen) : "—"}</TD>
                          <TD onClick={(e) => e.stopPropagation()}>
                            {can("apps:write") ? (
                              <Button size="sm" onClick={() => setReviewing(a)}>
                                Review
                              </Button>
                            ) : null}
                          </TD>
                        </TR>
                      ))}
                    </tbody>
                  </Table>
                )}
              </Card>
            </>
          )}
        </TabsContent>
      </Tabs>
      <Dialog open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        {open ? <AppSheet appKey={open} onReview={(a) => setReviewing(a)} /> : null}
      </Dialog>
      {reviewing ? <ReviewDialog app={reviewing} onClose={() => setReviewing(null)} /> : null}
    </>
  );
}

function Tile({ label, value, hint, tone, onClick }: { label: string; value: number; hint: string; tone?: Tone; onClick?: () => void }) {
  return (
    <button type="button" disabled={!onClick} onClick={onClick} className="rounded-lg border border-border bg-bg p-3 text-left shadow-card enabled:hover:border-primary">
      <p className="text-xs text-fg-muted">{label}</p>
      <p className={`text-2xl font-semibold ${tone === "warning" ? "text-warning" : ""}`}>{value}</p>
      <p className="text-xs text-fg-subtle">{hint}</p>
    </button>
  );
}

function DiscoveryCard({ on }: { on: boolean }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const policy = useQuery({
    queryKey: ["browser-policy"],
    queryFn: () => unwrap(api.GET("/v1/browser/policy")),
  });
  const toggle = useMutation({
    mutationFn: () => {
      const p = policy.data!;
      return withStepUp(() =>
        unwrap(
          api.PUT("/v1/browser/policy", {
            body: {
              apps: Object.fromEntries(p.apps.filter((a) => a.action !== "allow").map((a) => [a.key, a.action])),
              dlp: { detectors: p.dlp.detectors, custom: p.dlp.custom },
              uploads: p.uploads,
              message: p.message,
              saas_discovery: !on,
            },
          }),
        ),
      );
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["saas-apps"] });
      qc.invalidateQueries({ queryKey: ["browser-policy"] });
      toast.success(on ? "SaaS discovery is off" : "SaaS discovery is on", {
        description: "Browsers pick it up within a minute.",
      });
    },
  });
  return (
    <Card className="mb-5 flex flex-wrap items-center gap-3 p-4">
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium">SaaS discovery is {on ? "on" : "off"}</p>
        <p className="text-[13px] text-fg-muted">
          Browsers with the Nexus extension count visits to {on ? "the" : "about 1,700"} known work apps, and sign-ins with a password, per person per day. Nothing else about browsing is reported: no
          addresses, pages or anything typed. People see this in the extension. Set up the extension under{" "}
          <Link href="/ai-browsers" className="text-primary hover:underline">
            AI in browsers
          </Link>
          .
        </p>
      </div>
      <Button variant={on ? "secondary" : "primary"} loading={toggle.isPending} disabled={!policy.data} onClick={() => toggle.mutate()}>
        {on ? "Turn off" : "Turn on"}
      </Button>
      <ErrorBanner error={toggle.error} />
    </Card>
  );
}

function AppSheet({ appKey, onReview }: { appKey: string; onReview: (a: SaasApp) => void }) {
  const can = useCan();
  const one = useQuery({
    queryKey: ["saas-app", appKey],
    queryFn: () =>
      unwrap(
        api.GET("/v1/saas/apps/{key}", {
          params: { path: { key: appKey }, query: { days: 30 } },
        }),
      ),
  });
  const a = one.data?.app;
  return (
    <SheetContent title={a?.name ?? "App"}>
      <div className="flex-1 space-y-4 overflow-y-auto p-4 text-[13px]">
        <ErrorBanner error={one.error} />
        {!a ? (
          <Skeleton className="h-24" />
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <StatusPill tone={STATUS[a.status].tone}>{STATUS[a.status].label}</StatusPill>
              {a.status === "unapproved" ? <span className="text-fg-muted">{ACTION_LABEL[a.action]}</span> : null}
              <span className="text-fg-muted">· {a.category}</span>
              {can("apps:write") ? (
                <Button size="sm" className="ml-auto" onClick={() => onReview(a)}>
                  Review
                </Button>
              ) : null}
            </div>
            {a.notes ? <p className="text-fg-muted">{a.notes}</p> : null}
            {a.owner ? <p className="text-fg-muted">Owner: {a.owner.email}</p> : null}
            {a.sso ? (
              a.password_people ? (
                <div className="flex gap-2 rounded-md border border-warning/40 bg-warning-soft p-3">
                  <TriangleAlert className="size-4 shrink-0 text-warning" />
                  <p>
                    {a.name} is set up for single sign-on in Nexus, but {people(a.password_people)} signed in with a password. Consider requiring SSO in {a.name}&apos;s own settings.
                  </p>
                </div>
              ) : (
                <p className="flex items-center gap-1.5 text-success">
                  <Check className="size-4" /> Signed in to through Nexus SSO
                </p>
              )
            ) : can("apps:write") ? (
              <p>
                <Link href="/apps" className="text-primary hover:underline">
                  Set up single sign-on for {a.name}
                </Link>{" "}
                so access follows people&apos;s accounts, and offboarding removes it.
              </p>
            ) : null}
            <p className="text-xs text-fg-subtle">Seen on {a.hosts.join(", ")}</p>
            <div>
              <p className="mb-2 font-medium">{people(one.data!.people.length)} in the last 30 days</p>
              <ul className="divide-y divide-border rounded-md border border-border">
                {one.data!.people.map((p) => (
                  <li key={p.email} className="flex items-center gap-2 px-3 py-2">
                    <div className="min-w-0 flex-1">
                      <p className="truncate">{p.name || p.email}</p>
                      {p.name ? <p className="truncate text-xs text-fg-muted">{p.email}</p> : null}
                    </div>
                    {p.password_logins ? (
                      <span title="Signed in with a password" className="text-xs text-fg-muted">
                        <KeyRound className="inline size-3.5" />
                      </span>
                    ) : null}
                    {p.blocked ? (
                      <span title="Blocked visits" className="text-xs text-danger">
                        <ShieldBan className="inline size-3.5" /> {p.blocked}
                      </span>
                    ) : null}
                    <span className="text-xs text-fg-subtle">{timeAgo(p.last_seen)}</span>
                  </li>
                ))}
              </ul>
            </div>
          </>
        )}
      </div>
    </SheetContent>
  );
}

function ReviewDialog({ app, onClose }: { app: SaasApp; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [status, setStatus] = useState<Status>(app.status);
  const [action, setAction] = useState(app.action);
  const [notes, setNotes] = useState(app.notes);
  const save = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.PUT("/v1/saas/apps/{key}", {
            params: { path: { key: app.key } },
            body: {
              status,
              action: status === "unapproved" ? action : "allow",
              owner_id: app.owner?.id ?? null,
              notes,
            },
          }),
        ),
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["saas-apps"] });
      qc.invalidateQueries({ queryKey: ["saas-app", app.key] });
      toast.success(`${app.name}: ${STATUS[status].label.toLowerCase()}`, {
        description: status === "unapproved" && action !== "allow" ? "Browsers pick it up within a minute." : undefined,
      });
      onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={`Review ${app.name}`} description={app.people ? `${people(app.people)} used it in the last 30 days.` : undefined}>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Field label="Decision" htmlFor="rv-status">
            <Select id="rv-status" className="w-full" value={status} onChange={(e) => setStatus(e.target.value as Status)}>
              <option value="approved">Approved</option>
              <option value="unapproved">Unapproved</option>
              <option value="unreviewed">Not reviewed</option>
            </Select>
          </Field>
          {status === "unapproved" ? (
            <Field label="In browsers" htmlFor="rv-action" hint="Warnings let people continue for an hour; either way, it's counted here.">
              <Select id="rv-action" className="w-full" value={action} onChange={(e) => setAction(e.target.value as SaasApp["action"])}>
                <option value="allow">Allow, and keep counting</option>
                <option value="warn">Warn before opening it</option>
                <option value="block">Block it</option>
              </Select>
            </Field>
          ) : null}
          <Field label="Notes" htmlFor="rv-notes">
            <Input id="rv-notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Use the company workspace; approved by Security" />
          </Field>
          <ErrorBanner error={save.error} />
          <Button type="submit" variant="primary" loading={save.isPending}>
            Save
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}
