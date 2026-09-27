"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Laptop, Pencil, Plus, Trash2, Upload } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { Dialog, DialogContent, SheetContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime, timeAgo } from "@/lib/utils";

type Asset = Schemas["Asset"];
type Kind = Asset["kind"];
type Status = Asset["status"];

const KINDS: [Kind, string][] = [
  ["laptop", "Laptop"],
  ["desktop", "Desktop"],
  ["phone", "Phone"],
  ["tablet", "Tablet"],
  ["monitor", "Monitor"],
  ["peripheral", "Peripheral"],
  ["network", "Network"],
  ["server", "Server"],
  ["other", "Other"],
];
const STATUS: Record<Status, { tone: Tone; label: string }> = {
  in_stock: { tone: "neutral", label: "In stock" },
  assigned: { tone: "success", label: "Assigned" },
  in_repair: { tone: "warning", label: "In repair" },
  retired: { tone: "neutral", label: "Retired" },
  lost: { tone: "danger", label: "Lost" },
};
const WARRANTY: Record<Asset["warranty"], { tone: Tone; label: string } | null> = {
  none: null,
  active: null,
  expiring: { tone: "warning", label: "Warranty ending" },
  expired: { tone: "neutral", label: "Out of warranty" },
};
const money = (n: number, currency: string) => new Intl.NumberFormat(undefined, { style: "currency", currency, maximumFractionDigits: 0 }).format(n);

/** Asset management: hardware the organization owns, who has it, and its history. */
export default function AssetsPage() {
  return (
    <Suspense>
      <Assets />
    </Suspense>
  );
}

function Assets() {
  const can = useCan();
  const qc = useQueryClient();
  const params = useSearchParams();
  const [status, setStatus] = useState<Status | "">("");
  const [kind, setKind] = useState<Kind | "">("");
  const [q, setQ] = useState("");
  const assignedTo = params.get("assigned_to") ?? undefined;
  const [open, setOpen] = useState<string | null>(null);
  const [editing, setEditing] = useState<Asset | "new" | null>(null);
  const [importing, setImporting] = useState(false);
  const list = useQuery({
    queryKey: ["assets", status, kind, q, assignedTo],
    queryFn: () => unwrap(api.GET("/v1/assets", { params: { query: { ...(status ? { status } : {}), ...(kind ? { kind } : {}), ...(q ? { q } : {}), ...(assignedTo ? { assigned_to: assignedTo } : {}) } } })),
  });
  const fromDevices = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/assets/from-devices")),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      toast.success(r.created ? `Added ${r.created} enrolled device${r.created === 1 ? "" : "s"}` : "Every enrolled device already has an asset record");
    },
  });
  const s = list.data?.summary;
  const writable = can("devices:write");

  return (
    <>
      <PageHeader
        title="Assets"
        description="Hardware the organization owns, enrolled or not: who has it, where it is, what it cost and when its warranty ends."
        actions={
          writable ? (
            <div className="flex gap-2">
              <Button onClick={() => setImporting(true)}>
                <Upload /> Import
              </Button>
              <Button variant="primary" onClick={() => setEditing("new")}>
                <Plus /> Add asset
              </Button>
            </div>
          ) : null
        }
      />
      <ErrorBanner error={list.error ?? fromDevices.error} />
      {list.isPending ? (
        <Skeleton className="h-40" />
      ) : (
        <>
          <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-5">
            <Tile label="Assets" value={String(s?.total ?? 0)} hint={`${s?.assigned ?? 0} assigned · ${s?.in_stock ?? 0} in stock`} />
            <Tile label="To collect" value={String(s?.to_collect ?? 0)} hint="with people who've left" tone={s?.to_collect ? "warning" : undefined} />
            <Tile label="Warranty ending" value={String(s?.warranty_expiring ?? 0)} hint="in the next 90 days" tone={s?.warranty_expiring ? "warning" : undefined} />
            <Tile label="Value" value={s?.value.length ? s.value.map((v) => money(v.total, v.currency)).join(" + ") : "—"} hint="purchase cost, in service" />
            <Tile label="Enrolled, not recorded" value={String(s?.unenrolled_devices ?? 0)} hint="devices without an asset record" />
          </div>
          {s?.unenrolled_devices && writable ? (
            <Card className="mb-5 flex flex-wrap items-center gap-3 p-3 text-[13px]">
              <Laptop className="size-4 text-fg-muted" />
              <span className="flex-1">
                {s.unenrolled_devices} enrolled device{s.unenrolled_devices === 1 ? " has" : "s have"} no asset record. Add them, matched by serial number, with their current user.
              </span>
              <Button size="sm" loading={fromDevices.isPending} onClick={() => fromDevices.mutate()}>
                Add enrolled devices
              </Button>
            </Card>
          ) : null}
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
              <Input className="max-w-xs" placeholder="Search tag, serial, model, person" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search assets" />
              <Select value={status} onChange={(e) => setStatus(e.target.value as Status | "")} aria-label="Status">
                <option value="">All statuses</option>
                {Object.entries(STATUS).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v.label}
                  </option>
                ))}
              </Select>
              <Select value={kind} onChange={(e) => setKind(e.target.value as Kind | "")} aria-label="Kind">
                <option value="">All kinds</option>
                {KINDS.map(([k, l]) => (
                  <option key={k} value={k}>
                    {l}
                  </option>
                ))}
              </Select>
              {assignedTo ? (
                <Link href="/assets" className="text-[13px] text-primary hover:underline">
                  Showing one person&apos;s assets · show all
                </Link>
              ) : null}
            </div>
            {!list.data?.data.length ? (
              <EmptyState icon={<Boxes />} title="No assets" description="Add hardware one by one, import a spreadsheet, or add your enrolled devices." />
            ) : (
              <Table>
                <THead>
                  <TR>
                    <TH>Tag</TH>
                    <TH>Asset</TH>
                    <TH>Serial</TH>
                    <TH>With</TH>
                    <TH>Status</TH>
                    <TH>Warranty</TH>
                  </TR>
                </THead>
                <tbody>
                  {list.data.data.map((a) => (
                    <TR key={a.id} className="cursor-pointer" onClick={() => setOpen(a.id)}>
                      <TD className="font-mono text-xs">{a.tag}</TD>
                      <TD>
                        <p className="font-medium">{a.name || [a.make, a.model].filter(Boolean).join(" ") || KINDS.find(([k]) => k === a.kind)![1]}</p>
                        <p className="text-xs text-fg-muted">
                          {KINDS.find(([k]) => k === a.kind)![1]}
                          {a.device ? ` · enrolled as ${a.device.hostname}` : ""}
                        </p>
                      </TD>
                      <TD className="font-mono text-xs">{a.serial || "—"}</TD>
                      <TD>
                        {a.assigned_to ? (
                          <span className={a.assigned_to.left ? "text-warning" : ""}>
                            {a.assigned_to.name || a.assigned_to.email}
                            {a.assigned_to.left ? " (left: collect)" : ""}
                          </span>
                        ) : (
                          a.location || "—"
                        )}
                      </TD>
                      <TD>
                        <StatusPill tone={STATUS[a.status].tone}>{STATUS[a.status].label}</StatusPill>
                      </TD>
                      <TD className="whitespace-nowrap">
                        {WARRANTY[a.warranty] ? <StatusPill tone={WARRANTY[a.warranty]!.tone}>{WARRANTY[a.warranty]!.label}</StatusPill> : a.warranty_until ? new Date(`${a.warranty_until}T00:00:00`).toLocaleDateString() : "—"}
                      </TD>
                    </TR>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </>
      )}
      <Dialog open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        {open ? <AssetSheet id={open} onEdit={(a) => setEditing(a)} /> : null}
      </Dialog>
      {editing ? <AssetDialog asset={editing === "new" ? null : editing} onClose={() => setEditing(null)} /> : null}
      {importing ? <ImportDialog onClose={() => setImporting(false)} /> : null}
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

function AssetSheet({ id, onEdit }: { id: string; onEdit: (a: Asset) => void }) {
  const can = useCan();
  const qc = useQueryClient();
  const one = useQuery({ queryKey: ["asset", id], queryFn: () => unwrap(api.GET("/v1/assets/{id}", { params: { path: { id } } })) });
  const [who, setWho] = useState("");
  const [returned, setReturned] = useState<"in_stock" | "in_repair" | "retired" | "lost">("in_stock");
  const [note, setNote] = useState("");
  const users = useQuery({ queryKey: ["users", "picker", who], enabled: who.length > 1, queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { q: who, limit: 8, status: "active" } } })) });
  const done = () => {
    setWho("");
    setNote("");
    qc.invalidateQueries({ queryKey: ["asset", id] });
    qc.invalidateQueries({ queryKey: ["assets"] });
  };
  const checkout = useMutation({ mutationFn: (userId: string) => unwrap(api.POST("/v1/assets/{id}/checkout", { params: { path: { id } }, body: { user_id: userId, note } })), onSuccess: done });
  const checkin = useMutation({ mutationFn: () => unwrap(api.POST("/v1/assets/{id}/checkin", { params: { path: { id } }, body: { status: returned, note } })), onSuccess: done });
  const a = one.data?.asset;
  const writable = can("devices:write");
  const available = a && (a.status === "in_stock" || a.status === "in_repair");

  return (
    <SheetContent title={a ? `${a.tag}${a.name ? ` · ${a.name}` : ""}` : "Asset"}>
      <div className="flex-1 space-y-4 overflow-y-auto p-4 text-[13px]">
        <ErrorBanner error={one.error ?? checkout.error ?? checkin.error} />
        {!a ? (
          <Skeleton className="h-24" />
        ) : (
          <>
            <div className="flex items-center gap-2">
              <StatusPill tone={STATUS[a.status].tone}>{STATUS[a.status].label}</StatusPill>
              {a.assigned_to ? <span>with {a.assigned_to.name || a.assigned_to.email}</span> : null}
              {writable ? (
                <Button size="sm" className="ml-auto" onClick={() => onEdit(a)}>
                  <Pencil /> Edit
                </Button>
              ) : null}
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
              {(
                [
                  ["Kind", KINDS.find(([k]) => k === a.kind)![1]],
                  ["Make and model", [a.make, a.model].filter(Boolean).join(" ") || "—"],
                  ["Serial", a.serial || "—"],
                  ["Enrolled device", a.device ? <Link key="d" href={`/devices/${a.device.id}`} className="text-primary hover:underline">{a.device.hostname}</Link> : "—"],
                  ["Location", a.location || "—"],
                  ["Bought", [a.purchase_date ? new Date(`${a.purchase_date}T00:00:00`).toLocaleDateString() : "", a.purchase_cost !== null ? money(a.purchase_cost, a.currency) : "", a.vendor].filter(Boolean).join(" · ") || "—"],
                  ["Warranty until", a.warranty_until ? new Date(`${a.warranty_until}T00:00:00`).toLocaleDateString() : "—"],
                ] as [string, React.ReactNode][]
              ).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-fg-muted">{k}</dt>
                  <dd>{v}</dd>
                </div>
              ))}
            </dl>
            {a.notes ? <p className="whitespace-pre-wrap text-fg-muted">{a.notes}</p> : null}

            {writable && available ? (
              <div className="space-y-2 rounded-md border border-border p-3">
                <p className="font-medium">Check out</p>
                <Input placeholder="Search people" value={who} onChange={(e) => setWho(e.target.value)} aria-label="Person" />
                <Input placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} aria-label="Note" />
                <ul className="divide-y divide-border">
                  {users.data?.data.map((u) => (
                    <li key={u.id} className="flex items-center justify-between py-1.5">
                      <span>{u.display_name || u.email}</span>
                      <Button size="sm" loading={checkout.isPending} onClick={() => checkout.mutate(u.id)}>
                        Give to them
                      </Button>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            {writable && a.status === "assigned" ? (
              <div className="space-y-2 rounded-md border border-border p-3">
                <p className="font-medium">Check in</p>
                <Select className="w-full" value={returned} onChange={(e) => setReturned(e.target.value as typeof returned)} aria-label="Returned to">
                  <option value="in_stock">Back in stock</option>
                  <option value="in_repair">Sent for repair</option>
                  <option value="retired">Retired</option>
                  <option value="lost">Lost or stolen</option>
                </Select>
                <Input placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} aria-label="Note" />
                <Button size="sm" loading={checkin.isPending} onClick={() => checkin.mutate()}>
                  Check in
                </Button>
              </div>
            ) : null}

            <div>
              <p className="mb-2 font-medium">History</p>
              <ol className="space-y-1.5">
                {one.data!.history.map((h, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="w-28 shrink-0 text-xs text-fg-subtle" title={formatDateTime(h.at)}>
                      {timeAgo(h.at)}
                    </span>
                    <span>
                      {h.kind === "created" ? "Added" : h.kind === "checked_out" ? `Given to ${h.user ?? "someone"}` : h.kind === "checked_in" ? `Returned${h.user ? ` by ${h.user}` : ""}: ${STATUS[h.status as Status]?.label.toLowerCase() ?? h.status}` : "Details changed"}
                      {h.note ? <span className="text-fg-muted"> · {h.note}</span> : null}
                      {h.by ? <span className="text-xs text-fg-subtle"> · {h.by}</span> : null}
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          </>
        )}
      </div>
    </SheetContent>
  );
}

function AssetDialog({ asset, onClose }: { asset: Asset | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({
    tag: asset?.tag ?? "",
    name: asset?.name ?? "",
    kind: asset?.kind ?? ("laptop" as Kind),
    make: asset?.make ?? "",
    model: asset?.model ?? "",
    serial: asset?.serial ?? "",
    location: asset?.location ?? "",
    vendor: asset?.vendor ?? "",
    purchase_date: asset?.purchase_date ?? "",
    purchase_cost: asset?.purchase_cost === null || asset?.purchase_cost === undefined ? "" : String(asset.purchase_cost),
    currency: asset?.currency ?? "USD",
    warranty_until: asset?.warranty_until ?? "",
    notes: asset?.notes ?? "",
  });
  const body = () => ({ ...f, currency: f.currency.toUpperCase(), purchase_date: f.purchase_date || null, warranty_until: f.warranty_until || null, purchase_cost: f.purchase_cost === "" ? null : Number(f.purchase_cost) });
  const done = () => {
    qc.invalidateQueries({ queryKey: ["assets"] });
    if (asset) qc.invalidateQueries({ queryKey: ["asset", asset.id] });
    onClose();
  };
  const save = useMutation({ mutationFn: () => (asset ? unwrap(api.PUT("/v1/assets/{id}", { params: { path: { id: asset.id } }, body: body() })) : unwrap(api.POST("/v1/assets", { body: body() }))), onSuccess: done });
  const del = useMutation({ mutationFn: () => unwrap(api.DELETE("/v1/assets/{id}", { params: { path: { id: asset!.id } } })), onSuccess: done });
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={asset ? `Edit ${asset.tag}` : "Add an asset"} className="max-w-lg">
        <form
          className="grid grid-cols-2 gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Field label="Asset tag" htmlFor="as-tag">
            <Input id="as-tag" value={f.tag} onChange={set("tag")} placeholder="A-0042" autoFocus />
          </Field>
          <Field label="Kind" htmlFor="as-kind">
            <Select id="as-kind" className="w-full" value={f.kind} onChange={set("kind")}>
              {KINDS.map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Name" htmlFor="as-name">
            <Input id="as-name" value={f.name} onChange={set("name")} placeholder="Design team monitor" />
          </Field>
          <Field label="Serial number" htmlFor="as-serial">
            <Input id="as-serial" value={f.serial} onChange={set("serial")} />
          </Field>
          <Field label="Make" htmlFor="as-make">
            <Input id="as-make" value={f.make} onChange={set("make")} placeholder="Apple" />
          </Field>
          <Field label="Model" htmlFor="as-model">
            <Input id="as-model" value={f.model} onChange={set("model")} placeholder="MacBook Pro 14" />
          </Field>
          <Field label="Bought on" htmlFor="as-bought">
            <Input id="as-bought" type="date" value={f.purchase_date} onChange={set("purchase_date")} />
          </Field>
          <Field label="Cost" htmlFor="as-cost">
            <div className="flex gap-2">
              <Input id="as-cost" type="number" min={0} step="0.01" value={f.purchase_cost} onChange={set("purchase_cost")} />
              <Input className="w-20" maxLength={3} value={f.currency} onChange={set("currency")} aria-label="Currency" />
            </div>
          </Field>
          <Field label="Vendor" htmlFor="as-vendor">
            <Input id="as-vendor" value={f.vendor} onChange={set("vendor")} />
          </Field>
          <Field label="Warranty until" htmlFor="as-warranty">
            <Input id="as-warranty" type="date" value={f.warranty_until} onChange={set("warranty_until")} />
          </Field>
          <Field label="Location" htmlFor="as-location">
            <Input id="as-location" value={f.location} onChange={set("location")} placeholder="Berlin office" />
          </Field>
          <Field label="Notes" htmlFor="as-notes">
            <Input id="as-notes" value={f.notes} onChange={set("notes")} />
          </Field>
          <div className="col-span-2 space-y-2">
            <ErrorBanner error={save.error ?? del.error} />
            <div className="flex gap-2">
              <Button type="submit" variant="primary" loading={save.isPending} disabled={!f.tag.trim()}>
                Save
              </Button>
              {asset ? (
                <Button type="button" variant="danger-outline" loading={del.isPending} onClick={() => confirm(`Delete ${asset.tag} and its history? To keep the history, check it in as retired instead.`) && del.mutate()}>
                  <Trash2 /> Delete
                </Button>
              ) : null}
            </div>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

const COLUMNS = ["tag", "name", "kind", "make", "model", "serial", "location", "vendor", "purchase_date", "purchase_cost", "currency", "warranty_until", "notes", "assigned_to_email"] as const;

/** Splits a CSV line, honouring quoted fields ("a, b"). */
function splitCsv(line: string) {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') (cur += '"'), i++;
      else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") out.push(cur), (cur = "");
    else cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

function ImportDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [csv, setCsv] = useState("");
  const parse = () => {
    const lines = csv.split(/\r?\n/).filter((l) => l.trim());
    const header = splitCsv(lines[0] ?? "").map((h) => h.toLowerCase().replace(/\s+/g, "_"));
    const unknown = header.filter((h) => !(COLUMNS as readonly string[]).includes(h));
    if (!header.includes("tag")) throw new Error("The first line needs a tag column");
    if (unknown.length) throw new Error(`Unknown columns: ${unknown.join(", ")}`);
    return lines.slice(1).map((l) => {
      const cells = splitCsv(l);
      const row: Record<string, unknown> = {};
      header.forEach((h, i) => {
        const v = cells[i] ?? "";
        if (v === "") return;
        row[h] = h === "purchase_cost" ? Number(v) : h === "kind" ? v.toLowerCase() : v;
      });
      return row;
    });
  };
  const run = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/assets/import", { body: { rows: parse() as never } })),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      toast.success(`${r.created} added, ${r.updated} updated`, { description: r.errors.length ? `${r.errors.length} rows need a look: ${r.errors.slice(0, 3).map((e) => `row ${e.row}: ${e.message}`).join("; ")}` : undefined });
      if (!r.errors.length) onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Import assets" description="Paste a CSV with a header row. Existing tags are updated; new ones are added. Name someone by assigned_to_email to mark the asset as theirs." className="max-w-2xl">
        <div className="space-y-3">
          <p className="font-mono text-[11px] text-fg-muted">{COLUMNS.join(",")}</p>
          <textarea
            rows={10}
            className="w-full rounded-md border border-border bg-bg px-2.5 py-1.5 font-mono text-xs"
            value={csv}
            onChange={(e) => setCsv(e.target.value)}
            placeholder={"tag,name,kind,serial,assigned_to_email\nA-0042,Design monitor,monitor,CN0ABC123,ana@example.com"}
            aria-label="CSV"
          />
          <ErrorBanner error={run.error} />
          <Button variant="primary" loading={run.isPending} disabled={!csv.trim()} onClick={() => run.mutate()}>
            Import
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
