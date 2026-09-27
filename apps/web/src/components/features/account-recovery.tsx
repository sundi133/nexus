"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, LifeBuoy, Lock } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Field, Input } from "@/components/ui/input";
import { Card, CardHeader, ErrorBanner, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, fieldErrors, unwrap } from "@/lib/api";
import { timeAgo } from "@/lib/utils";

/** AUTH-02: one-time codes for when your phone or security key isn't available. */
export function RecoveryCodesCard({ hasFactor }: { hasFactor: boolean }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const info = useQuery({ queryKey: ["recovery-codes"], queryFn: () => unwrap(api.GET("/v1/me/recovery-codes")) });
  const [codes, setCodes] = useState<string[] | null>(null);
  const gen = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/me/recovery-codes", {}))),
    onSuccess: (r) => {
      setCodes(r.codes);
      qc.invalidateQueries({ queryKey: ["recovery-codes"] });
    },
  });
  const remaining = info.data?.remaining ?? 0;
  const download = () => {
    const blob = new Blob([`Votal Nexus recovery codes\nEach code works once.\n\n${codes!.join("\n")}\n`], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "nexus-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <LifeBuoy className="size-4 text-fg-muted" /> Recovery codes
          </span>
        }
        description="Each code signs you in once if you lose your phone or security key. Keep them somewhere safe, like a password manager."
        actions={
          hasFactor ? (
            <Button variant={remaining ? "secondary" : "primary"} loading={gen.isPending} onClick={() => gen.mutate()}>
              {remaining ? "Generate new codes" : "Generate codes"}
            </Button>
          ) : null
        }
      />
      <div className="px-4 py-3 text-[13px]">
        <ErrorBanner error={gen.error} />
        {!hasFactor ? (
          <p className="text-fg-muted">Add a sign-in method first; recovery codes back it up.</p>
        ) : remaining ? (
          <p className="flex items-center gap-2">
            <StatusPill tone={remaining <= 2 ? "warning" : "success"}>{remaining} left</StatusPill>
            <span className="text-fg-muted">Created {timeAgo(info.data?.created_at)}. Generating new ones cancels these.</span>
          </p>
        ) : (
          <p className="text-warning">You have no recovery codes. If you lose your sign-in methods, only an admin can help you back in.</p>
        )}
      </div>
      {codes ? (
        <Dialog open onOpenChange={(o) => !o && setCodes(null)}>
          <DialogContent title="Your recovery codes" description="Save them now: they won't be shown again. Each works once.">
            <ol className="grid grid-cols-2 gap-x-6 gap-y-1.5 rounded-md border border-border bg-bg-subtle px-5 py-4 font-mono text-[13px]">
              {codes.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ol>
            <div className="mt-3">
              <CopyField value={codes.join("\n")} label="Copy all" />
            </div>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="secondary" onClick={download}>
                <Download /> Download
              </Button>
              <Button variant="primary" onClick={() => (setCodes(null), toast.success("Recovery codes saved"))}>
                I've saved them
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      ) : null}
    </Card>
  );
}

/** PORT-02: change your password; other sessions are signed out. */
export function ChangePasswordCard() {
  const withStepUp = useStepUp();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const change = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.PUT("/v1/me/password", { body: { current_password: current, new_password: next } }))),
    onSuccess: () => {
      setCurrent("");
      setNext("");
      toast.success("Password changed", { description: "Your other sessions were signed out." });
    },
  });
  const errs = fieldErrors(change.error);
  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <Lock className="size-4 text-fg-muted" /> Password
          </span>
        }
        description="At least 12 characters. Passwords found in known data breaches are refused."
      />
      <form
        className="grid gap-3 p-4 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate();
        }}
      >
        <Field label="Current password" htmlFor="cur-pw" error={errs.current_password}>
          <Input id="cur-pw" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </Field>
        <Field label="New password" htmlFor="new-pw" error={errs.password ?? errs.new_password}>
          <Input id="new-pw" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        </Field>
        <Button type="submit" variant="secondary" loading={change.isPending} disabled={!current || next.length < 12}>
          Change password
        </Button>
        <div className="sm:col-span-3">
          <ErrorBanner error={change.error && !errs.current_password ? change.error : null} />
        </div>
      </form>
    </Card>
  );
}
