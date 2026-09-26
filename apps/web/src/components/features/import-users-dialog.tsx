"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FileUp } from "lucide-react";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { ErrorBanner, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { pluralize } from "@/lib/utils";

const TONE = { create: "success", skip: "neutral", error: "danger" } as const;
const TEMPLATE = "email,first name,last name,title,department,groups\nana@example.com,Ana,Ruiz,Engineer,Engineering,Engineering;All staff\n";

/** CSV import with a mandatory preview: nothing is written until the admin has seen every row's outcome. */
export function ImportUsersDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const input = useRef<HTMLInputElement>(null);
  const [csv, setCsv] = useState("");
  const [fileName, setFileName] = useState("");
  const [invite, setInvite] = useState(true);
  const [preview, setPreview] = useState<Schemas["ImportResult"] | null>(null);

  const reset = () => {
    setCsv("");
    setFileName("");
    setPreview(null);
  };
  const dryRun = useMutation({
    mutationFn: (text: string) => unwrap(api.POST("/v1/users/import", { body: { csv: text, dry_run: true, invite } })),
    onSuccess: setPreview,
    onError: () => {},
  });
  const commit = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/users/import", { body: { csv, dry_run: false, invite } })),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["users"] });
      qc.invalidateQueries({ queryKey: ["groups"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
      toast.success(`Imported ${pluralize(r.summary.create, "user")}`, { description: invite ? "Invitations are on their way." : undefined });
      reset();
      onOpenChange(false);
    },
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v) reset();
        onOpenChange(v);
      }}
    >
      <DialogContent title="Import users from CSV" description="You'll see a preview before anything is created. Existing people are skipped, never overwritten." className="max-w-2xl">
        {!preview ? (
          <div className="space-y-4">
            <button
              type="button"
              onClick={() => input.current?.click()}
              className="flex w-full flex-col items-center gap-2 rounded-lg border border-dashed border-border-strong px-4 py-8 text-[13px] text-fg-muted hover:bg-bg-subtle"
            >
              <FileUp className="size-5" />
              {fileName || "Choose a .csv file"}
              <span className="text-xs text-fg-subtle">Columns: email, first name, last name, title, department, groups (separated by ;)</span>
            </button>
            <input
              ref={input}
              type="file"
              accept=".csv,text/csv"
              className="hidden"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (!f) return;
                const text = await f.text();
                setFileName(f.name);
                setCsv(text);
                dryRun.mutate(text);
              }}
            />
            <ErrorBanner error={dryRun.error} />
            <div className="flex items-center justify-between">
              <a href={`data:text/csv;charset=utf-8,${encodeURIComponent(TEMPLATE)}`} download="nexus-users-template.csv" className="text-[13px] text-primary hover:underline">
                Download a template
              </a>
              <label className="flex items-center gap-2 text-[13px]">
                <input type="checkbox" checked={invite} onChange={(e) => setInvite(e.target.checked)} /> Email invitations
              </label>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2 text-[13px]">
              <StatusPill tone="success">{preview.summary.create} to create</StatusPill>
              <StatusPill tone="neutral">{preview.summary.skip} skipped</StatusPill>
              {preview.summary.error ? <StatusPill tone="danger">{preview.summary.error} with errors</StatusPill> : null}
              {preview.summary.new_groups.length ? (
                <span className="text-xs text-fg-muted">New groups: {preview.summary.new_groups.join(", ")}</span>
              ) : null}
            </div>
            <div className="max-h-72 overflow-y-auto rounded-md border border-border">
              <Table>
                <THead>
                  <tr>
                    <TH>Line</TH>
                    <TH>Email</TH>
                    <TH>Result</TH>
                  </tr>
                </THead>
                <tbody>
                  {preview.rows.map((r) => (
                    <TR key={r.line}>
                      <TD className="font-mono text-xs text-fg-subtle">{r.line}</TD>
                      <TD>
                        <span className="block">{r.email || "—"}</span>
                        {r.groups.length ? <span className="text-xs text-fg-subtle">{r.groups.join(", ")}</span> : null}
                      </TD>
                      <TD>
                        <StatusPill tone={TONE[r.action]}>{r.action}</StatusPill>
                        <span className="ml-2 text-xs text-fg-muted">{r.message}</span>
                      </TD>
                    </TR>
                  ))}
                </tbody>
              </Table>
            </div>
            <ErrorBanner error={commit.error} />
            <div className="flex justify-end gap-2">
              <Button onClick={reset}>Choose another file</Button>
              <Button variant="primary" disabled={!preview.summary.create} loading={commit.isPending} onClick={() => commit.mutate()}>
                Import {pluralize(preview.summary.create, "user")}
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
