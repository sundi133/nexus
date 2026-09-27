"use client";

import { Download, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";

const SHOWN = 500;

/** osquery rows (every value a string) as a searchable table, with CSV download. */
export function RowsTable({ rows, columns, file, empty = "No rows" }: { rows: Record<string, string>[]; columns?: string[]; file: string; empty?: string }) {
  const [q, setQ] = useState("");
  const cols = useMemo(() => columns ?? [...new Set(rows.flatMap((r) => Object.keys(r)))], [rows, columns]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return needle ? rows.filter((r) => cols.some((c) => (r[c] ?? "").toLowerCase().includes(needle))) : rows;
  }, [rows, cols, q]);
  if (!rows.length) return <EmptyState title={empty} />;
  return (
    <>
      <div className="flex items-center gap-2 border-b border-border px-4 py-2">
        <div className="relative max-w-xs flex-1">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-fg-subtle" aria-hidden />
          <Input className="pl-8" placeholder="Filter rows" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter rows" />
        </div>
        <span className="text-xs text-fg-muted">
          {filtered.length === rows.length ? `${rows.length.toLocaleString()} rows` : `${filtered.length.toLocaleString()} of ${rows.length.toLocaleString()}`}
          {filtered.length > SHOWN ? ` (showing ${SHOWN})` : ""}
        </span>
        <Button size="sm" variant="ghost" className="ml-auto" onClick={() => downloadCsv(file, cols, filtered)}>
          <Download /> CSV
        </Button>
      </div>
      <Table>
        <THead>
          <tr>
            {cols.map((c) => (
              <TH key={c} className="whitespace-nowrap">
                {c === "_device" ? "device" : c}
              </TH>
            ))}
          </tr>
        </THead>
        <tbody>
          {filtered.slice(0, SHOWN).map((r, i) => (
            <TR key={i}>
              {cols.map((c) => (
                <TD key={c} className="max-w-[28rem] truncate font-mono text-xs" title={r[c]}>
                  {r[c] ?? ""}
                </TD>
              ))}
            </TR>
          ))}
        </tbody>
      </Table>
    </>
  );
}

function downloadCsv(file: string, cols: string[], rows: Record<string, string>[]) {
  // Quote every cell; neutralise spreadsheet formulas (a value starting with = + - @).
  const cell = (v: string) => `"${(/^[=+\-@]/.test(v) ? `'${v}` : v).replace(/"/g, '""')}"`;
  const csv = [cols.map(cell).join(","), ...rows.map((r) => cols.map((c) => cell(r[c] ?? "")).join(","))].join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: `${file}.csv` });
  a.click();
  URL.revokeObjectURL(url);
}

export const TABLE_TITLES: Record<string, { title: string; description: string; columns: string[] }> = {
  software: { title: "Software", description: "Installed applications and packages", columns: ["name", "version", "source", "publisher"] },
  listening_ports: { title: "Listening ports", description: "Processes accepting network connections", columns: ["process", "port", "protocol", "address"] },
  usb_devices: { title: "USB devices", description: "Connected USB hardware", columns: ["vendor", "model", "vendor_id", "model_id", "removable"] },
  browser_extensions: { title: "Browser extensions", description: "Chrome, Edge, Brave and Firefox extensions, per user", columns: ["browser", "name", "version", "user", "profile", "identifier"] },
  startup_items: { title: "Startup items", description: "What runs at boot or sign-in", columns: ["name", "type", "source", "status", "path"] },
};

/** A known table's columns first, in their natural order, then anything else the rows have. */
export function orderedColumns(name: string, rows: Record<string, string>[]) {
  const present = new Set(rows.flatMap((r) => Object.keys(r)));
  const known = (TABLE_TITLES[name]?.columns ?? []).filter((c) => present.has(c));
  return [...known, ...[...present].filter((c) => !known.includes(c))];
}
