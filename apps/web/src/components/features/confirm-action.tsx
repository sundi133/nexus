"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";

/**
 * Confirmation for consequential actions (docs/UI.md §1.4): states the blast
 * radius, asks for a reason for the audit log, and optionally requires typing
 * a confirmation phrase.
 */
export function ConfirmAction({
  open,
  onOpenChange,
  title,
  effects,
  confirmLabel,
  danger,
  typeToConfirm,
  askReason = true,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  effects: string[];
  confirmLabel: string;
  danger?: boolean;
  typeToConfirm?: string;
  askReason?: boolean;
  onConfirm: (reason: string) => Promise<unknown>;
}) {
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const close = (v: boolean) => {
    if (!v) {
      setReason("");
      setTyped("");
      setError(null);
    }
    onOpenChange(v);
  };

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent title={title} description="This will:">
        <form
          className="space-y-4"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            try {
              await onConfirm(reason);
              close(false);
            } catch (err) {
              setError(err);
            } finally {
              setBusy(false);
            }
          }}
        >
          <ul className="-mt-2 list-disc space-y-1 pl-5 text-[13px]">
            {effects.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
          <ErrorBanner error={error} />
          {askReason ? (
            <Field label="Reason" htmlFor="reason" hint="Saved to the audit log.">
              <Input id="reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Suspicious sign-in from new country" autoFocus />
            </Field>
          ) : null}
          {typeToConfirm ? (
            <Field label={`Type ${typeToConfirm} to confirm`} htmlFor="typed">
              <Input id="typed" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
            </Field>
          ) : null}
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={() => close(false)}>
              Cancel
            </Button>
            <Button type="submit" variant={danger ? "danger" : "primary"} loading={busy} disabled={!!typeToConfirm && typed !== typeToConfirm}>
              {confirmLabel}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
