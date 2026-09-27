"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Pencil, Plus, Receipt, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { Dialog, DialogContent, SheetContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

type License = Schemas["SaasLicense"];
const money = (n: number, currency: string) =>
  new Intl.NumberFormat(undefined, {
    style: "currency",
    currency,
    maximumFractionDigits: n % 1 ? 2 : 0,
  }).format(n);
const HOLDER: Record<string, { tone: Tone; label: string }> = {
  active: { tone: "success", label: "Uses it" },
  inactive: { tone: "warning", label: "Not used" },
  departed: { tone: "danger", label: "Left" },
  unknown: { tone: "neutral", label: "Can't tell" },
};

/** Licenses: what the organization pays for each app, and which seats are used. */
export function SaasLicenses() {
  const can = useCan();
  const list = useQuery({
    queryKey: ["saas-licenses"],
    queryFn: () => unwrap(api.GET("/v1/saas/licenses", { params: { query: { days: 30 } } })),
  });
  const [editing, setEditing] = useState<License | "new" | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const t = list.data?.totals ?? [];

  return (
    <>
      <ErrorBanner error={list.error} />
      {list.isPending ? (
        <Skeleton className="h-40" />
      ) : (
        <>
          <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
            <Tile label="Spend per year" value={t.length ? t.map((x) => money(x.annual_cost, x.currency)).join(" + ") : "—"} hint={`${t.reduce((n, x) => n + x.seats, 0)} seats`} />
            <Tile
              label="Could reclaim"
              value={t.length ? t.map((x) => money(x.reclaimable_annual, x.currency)).join(" + ") : "—"}
              hint={`${t.reduce((n, x) => n + x.reclaimable, 0)} seats unused, unassigned or held by leavers`}
              tone={t.some((x) => x.reclaimable) ? "warning" : undefined}
            />
            <Tile label="Renewing soon" value={String(list.data?.renewing_soon ?? 0)} hint="in the next 60 days" tone={list.data?.renewing_soon ? "warning" : undefined} />
            <Tile label="Licenses" value={String(list.data?.data.length ?? 0)} hint="apps you pay for" />
          </div>
          <Card className="overflow-hidden">
            <div className="flex items-center justify-between border-b border-border p-3">
              <p className="text-[13px] text-fg-muted">A seat counts as used if its holder opened the app in a managed browser, or signed in to it through Nexus, in the last 30 days.</p>
              {can("apps:write") ? (
                <Button size="sm" variant="primary" onClick={() => setEditing("new")}>
                  <Plus /> Add license
                </Button>
              ) : null}
            </div>
            {!list.data?.data.length ? (
              <EmptyState icon={<Receipt />} title="No licenses yet" description="Add what you pay for an app (seats, price, renewal) to see which seats are used and what you could save." />
            ) : (
              <Table>
                <THead>
                  <TR>
                    <TH>App</TH>
                    <TH>Seats</TH>
                    <TH>Used</TH>
                    <TH>Per year</TH>
                    <TH>Could reclaim</TH>
                    <TH>Renews</TH>
                    <TH />
                  </TR>
                </THead>
                <tbody>
                  {list.data.data.map((l) => (
                    <TR key={l.id} className="cursor-pointer" onClick={() => setOpen(l.id)}>
                      <TD>
                        <p className="font-medium">{l.app_name}</p>
                        <p className="text-xs text-fg-muted">{[l.plan, l.seat_source === "sso" ? "seats from SSO" : "seat list"].filter(Boolean).join(" · ")}</p>
                      </TD>
                      <TD>
                        {l.holders}/{l.seats}
                      </TD>
                      <TD>
                        {l.activity_from.length ? (
                          `${l.active} of ${l.holders}`
                        ) : (
                          <span className="text-fg-subtle" title="Turn on SaaS discovery or set up SSO to see use">
                            —
                          </span>
                        )}
                      </TD>
                      <TD>{money(l.annual_cost, l.currency)}</TD>
                      <TD className={l.reclaimable ? "text-warning" : "text-fg-subtle"}>{l.reclaimable ? `${l.reclaimable} · ${money(l.reclaimable_annual, l.currency)}` : "—"}</TD>
                      <TD className="whitespace-nowrap">
                        {l.renews_on ? (
                          <span className={l.renews_soon ? "inline-flex items-center gap-1 text-warning" : ""}>
                            {l.renews_soon ? <CalendarClock className="size-3.5" /> : null}
                            {new Date(`${l.renews_on}T00:00:00`).toLocaleDateString()}
                          </span>
                        ) : (
                          "—"
                        )}
                      </TD>
                      <TD onClick={(e) => e.stopPropagation()}>
                        {can("apps:write") ? (
                          <Button size="icon" variant="ghost" aria-label="Edit" onClick={() => setEditing(l)}>
                            <Pencil />
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
      {editing ? <LicenseDialog license={editing === "new" ? null : editing} onClose={() => setEditing(null)} /> : null}
      <Dialog open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        {open ? <LicenseSheet id={open} /> : null}
      </Dialog>
    </>
  );
}

function Tile({ label, value, hint, tone }: { label: string; value: string; hint: string; tone?: Tone }) {
  return (
    <div className="rounded-lg border border-border bg-bg p-3 shadow-card">
      <p className="text-xs text-fg-muted">{label}</p>
      <p className={`truncate text-xl font-semibold ${tone === "warning" ? "text-warning" : ""}`}>{value}</p>
      <p className="text-xs text-fg-subtle">{hint}</p>
    </div>
  );
}

function LicenseSheet({ id }: { id: string }) {
  const can = useCan();
  const qc = useQueryClient();
  const one = useQuery({
    queryKey: ["saas-license", id],
    queryFn: () =>
      unwrap(
        api.GET("/v1/saas/licenses/{id}", {
          params: { path: { id }, query: { days: 30 } },
        }),
      ),
  });
  const [list, setList] = useState<string | null>(null);
  const saveList = useMutation({
    mutationFn: () =>
      unwrap(
        api.PUT("/v1/saas/licenses/{id}/holders", {
          params: { path: { id } },
          body: {
            emails: (list ?? "")
              .split(/[\s,;]+/)
              .map((e) => e.trim())
              .filter(Boolean),
          },
        }),
      ),
    onSuccess: (r) => {
      toast.success(`${r.holders} seat holders`, {
        description: `${r.added} added, ${r.removed} removed`,
      });
      setList(null);
      qc.invalidateQueries({ queryKey: ["saas-license", id] });
      qc.invalidateQueries({ queryKey: ["saas-licenses"] });
    },
  });
  const l = one.data?.license;
  return (
    <SheetContent title={l ? `${l.app_name}${l.plan ? ` · ${l.plan}` : ""}` : "License"}>
      <div className="flex-1 space-y-4 overflow-y-auto p-4 text-[13px]">
        <ErrorBanner error={one.error ?? saveList.error} />
        {!l ? (
          <Skeleton className="h-24" />
        ) : (
          <>
            <p>
              {l.seats} seats at {money(l.unit_cost, l.currency)} per seat per {l.billing === "monthly" ? "month" : "year"}: {money(l.annual_cost, l.currency)} a year.
              {l.reclaimable ? ` ${l.reclaimable} could be reclaimed (${money(l.reclaimable_annual, l.currency)} a year).` : ""}
            </p>
            {!l.activity_from.length ? <p className="text-fg-muted">Nexus can't see whether people use {l.app_name}: turn on SaaS discovery, or set it up for single sign-on.</p> : null}
            {l.seat_source === "sso" && !l.sso_app ? <p className="text-warning">Seats come from SSO assignments, but {l.app_name} isn&apos;t set up for single sign-on in Nexus yet.</p> : null}
            {l.seat_source === "list" && can("apps:write") ? (
              list === null ? (
                <Button size="sm" onClick={() => setList(one.data!.holders.map((h) => h.email).join("\n"))}>
                  Edit seat holders
                </Button>
              ) : (
                <div className="space-y-2">
                  <Field label="Seat holders" htmlFor="lic-holders" hint="One email per line (or paste from the app's admin export).">
                    <textarea
                      id="lic-holders"
                      rows={8}
                      className="w-full rounded-md border border-border bg-bg px-2.5 py-1.5 font-mono text-xs"
                      value={list}
                      onChange={(e) => setList(e.target.value)}
                    />
                  </Field>
                  <div className="flex gap-2">
                    <Button size="sm" variant="primary" loading={saveList.isPending} onClick={() => saveList.mutate()}>
                      Save
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setList(null)}>
                      Cancel
                    </Button>
                  </div>
                </div>
              )
            ) : null}
            <ul className="divide-y divide-border rounded-md border border-border">
              {one.data!.holders.map((h) => (
                <li key={h.email} className="flex items-center gap-2 px-3 py-2">
                  <div className="min-w-0 flex-1">
                    <p className="truncate">{h.name || h.email}</p>
                    {h.name ? <p className="truncate text-xs text-fg-muted">{h.email}</p> : null}
                  </div>
                  {h.last_used ? (
                    <span className="text-xs text-fg-subtle">
                      {timeAgo(h.last_used)}
                      {h.via === "sso" ? " · SSO" : ""}
                    </span>
                  ) : null}
                  <StatusPill tone={HOLDER[h.status]!.tone}>{HOLDER[h.status]!.label}</StatusPill>
                </li>
              ))}
              {!one.data!.holders.length ? <li className="px-3 py-2 text-fg-muted">Nobody holds a seat yet.</li> : null}
            </ul>
          </>
        )}
      </div>
    </SheetContent>
  );
}

function LicenseDialog({ license, onClose }: { license: License | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [q, setQ] = useState(license?.app_name ?? "");
  const [appKey, setAppKey] = useState(license?.app_key ?? "");
  const [f, setF] = useState({
    plan: license?.plan ?? "",
    seats: String(license?.seats ?? 10),
    unit_cost: String(license?.unit_cost ?? ""),
    currency: license?.currency ?? "USD",
    billing: license?.billing ?? ("annual" as "annual" | "monthly"),
    renews_on: license?.renews_on ?? "",
    seat_source: license?.seat_source ?? ("sso" as "sso" | "list"),
    notes: license?.notes ?? "",
  });
  const catalog = useQuery({
    queryKey: ["saas-catalog", q],
    enabled: !appKey && q.length > 1,
    queryFn: () => unwrap(api.GET("/v1/saas/catalog", { params: { query: { q, limit: 8 } } })),
  });
  const body = () => ({
    app_key: appKey,
    plan: f.plan,
    seats: Number(f.seats),
    unit_cost: Number(f.unit_cost || 0),
    currency: f.currency.toUpperCase(),
    billing: f.billing,
    renews_on: f.renews_on || null,
    seat_source: f.seat_source,
    owner_id: license?.owner?.id ?? null,
    notes: f.notes,
  });
  const done = () => {
    qc.invalidateQueries({ queryKey: ["saas-licenses"] });
    onClose();
  };
  const save = useMutation({
    mutationFn: () =>
      license
        ? unwrap(
            api.PUT("/v1/saas/licenses/{id}", {
              params: { path: { id: license.id } },
              body: body(),
            }),
          )
        : unwrap(api.POST("/v1/saas/licenses", { body: body() })),
    onSuccess: done,
  });
  const del = useMutation({
    mutationFn: () =>
      unwrap(
        api.DELETE("/v1/saas/licenses/{id}", {
          params: { path: { id: license!.id } },
        }),
      ),
    onSuccess: done,
  });
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={license ? `Edit ${license.app_name} license` : "Add a license"}>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Field label="App" htmlFor="lic-app">
            <div className="relative">
              <Input id="lic-app" value={q} onChange={(e) => (setQ(e.target.value), setAppKey(""))} placeholder="Search 1,700 apps" autoComplete="off" disabled={!!license} />
              {!appKey && catalog.data?.data.length ? (
                <ul className="absolute z-10 mt-1 w-full rounded-md border border-border bg-bg shadow-card">
                  {catalog.data.data.map((a) => (
                    <li key={a.key}>
                      <button type="button" className="w-full px-2.5 py-1.5 text-left text-[13px] hover:bg-bg-muted" onClick={() => (setAppKey(a.key), setQ(a.name))}>
                        {a.name} <span className="text-xs text-fg-muted">· {a.category}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Plan" htmlFor="lic-plan">
              <Input id="lic-plan" value={f.plan} onChange={set("plan")} placeholder="Business" />
            </Field>
            <Field label="Seats" htmlFor="lic-seats">
              <Input id="lic-seats" type="number" min={0} value={f.seats} onChange={set("seats")} />
            </Field>
            <Field label="Price per seat" htmlFor="lic-cost">
              <Input id="lic-cost" type="number" min={0} step="0.01" value={f.unit_cost} onChange={set("unit_cost")} placeholder="12.50" />
            </Field>
            <Field label="Billed" htmlFor="lic-billing">
              <Select id="lic-billing" className="w-full" value={f.billing} onChange={set("billing")}>
                <option value="monthly">Monthly</option>
                <option value="annual">Yearly</option>
              </Select>
            </Field>
            <Field label="Currency" htmlFor="lic-cur">
              <Input id="lic-cur" maxLength={3} value={f.currency} onChange={set("currency")} />
            </Field>
            <Field label="Renews on" htmlFor="lic-renew">
              <Input id="lic-renew" type="date" value={f.renews_on} onChange={set("renews_on")} />
            </Field>
          </div>
          <Field label="Who holds the seats" htmlFor="lic-source">
            <Select id="lic-source" className="w-full" value={f.seat_source} onChange={set("seat_source")}>
              <option value="sso">People assigned to the app in Nexus SSO</option>
              <option value="list">A list of emails (from the app&apos;s admin console)</option>
            </Select>
          </Field>
          <Field label="Notes" htmlFor="lic-notes">
            <Input id="lic-notes" value={f.notes} onChange={set("notes")} placeholder="Contract #, vendor contact" />
          </Field>
          <ErrorBanner error={save.error ?? del.error} />
          <div className="flex gap-2">
            <Button type="submit" variant="primary" loading={save.isPending} disabled={!appKey || f.seats === ""}>
              Save
            </Button>
            {license ? (
              <Button type="button" variant="danger-outline" loading={del.isPending} onClick={() => confirm(`Remove the ${license.app_name} license?`) && del.mutate()}>
                <Trash2 /> Remove
              </Button>
            ) : null}
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
