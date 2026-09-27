"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Card, CardHeader, StatusPill, type Tone } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, formatDateTime } from "@/lib/utils";

const TITLE: Record<string, string> = { firewall: "Firewall", screen_lock: "Screen lock", disk_encryption: "Disk encryption (BitLocker)" };
const STATUS: Record<string, { label: string; tone: Tone }> = {
  compliant: { label: "In place", tone: "success" },
  applied: { label: "Fixed", tone: "success" },
  pending_restart: { label: "Fixed, after a restart", tone: "warning" },
  failed: { label: "Couldn't fix", tone: "danger" },
  unsupported: { label: "Not on this OS", tone: "neutral" },
};

/** What the agent does about the settings device policies ask it to fix, and escrowed recovery keys. */
export function DeviceSettingsCard({ device, className }: { device: Schemas["DeviceDetail"]; className?: string }) {
  const can = useCan();
  const withStepUp = useStepUp();
  const [keys, setKeys] = useState<Schemas["RecoveryKey"][] | null>(null);
  const reveal = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.GET("/v1/devices/{id}/recovery-keys", { params: { path: { id: device.id } } }))),
    onSuccess: (r) => setKeys(r.data),
    onError: (e) => toast.error(e instanceof Error ? e.message : "Couldn't reveal the key"),
  });
  const s = device.settings;
  if (!s.results.length && !s.recovery_keys) return null;
  return (
    <Card className={cn("overflow-hidden", className)}>
      <CardHeader
        title="Settings Nexus enforces"
        description={
          <>
            From device policies set to fix, not just report (<Link href="/device-policies" className="underline underline-offset-2">Device policies</Link>). Re-applied hourly
            {s.reported_at ? `; last reported ${formatDateTime(s.reported_at)}` : ""}.
          </>
        }
        actions={
          s.recovery_keys && can("devices:recovery_keys") ? (
            <Button size="sm" onClick={() => reveal.mutate()} loading={reveal.isPending}>
              <KeyRound className="size-3.5" /> Reveal recovery key
            </Button>
          ) : null
        }
      />
      {s.results.length ? (
        <ul className="divide-y divide-border">
          {s.results.map((r) => (
            <li key={r.key} className="flex items-start justify-between gap-3 px-4 py-2.5 text-[13px]">
              <div className="min-w-0">
                <p className="font-medium">{TITLE[r.key] ?? r.key}</p>
                {r.detail ? <p className="text-xs text-fg-muted">{r.detail}</p> : null}
              </div>
              <StatusPill tone={STATUS[r.status]?.tone ?? "neutral"}>{STATUS[r.status]?.label ?? r.status}</StatusPill>
            </li>
          ))}
        </ul>
      ) : null}
      {s.recovery_keys ? <p className="border-t border-border px-4 py-2.5 text-xs text-fg-muted">BitLocker recovery key escrowed. Revealing it is recorded in the audit log.</p> : null}

      <Dialog open={!!keys} onOpenChange={(o) => !o && setKeys(null)}>
        <DialogContent title={`Recovery keys for ${device.hostname}`} description="Read the key to the person at the BitLocker recovery screen. This reveal is in the audit log.">
          <div className="space-y-3">
            {keys?.map((k) => (
              <div key={`${k.volume}${k.key_id}`}>
                <CopyField label={`${k.volume} · key ID ${k.key_id.slice(1, 9)}${k.retired_at ? " · retired" : ""}`} value={k.password} secret />
                <p className="mt-1 text-[11px] text-fg-subtle">
                  Escrowed {formatDateTime(k.escrowed_at)}
                  {k.retired_at ? `; no longer on the device since ${formatDateTime(k.retired_at)} (for older backups)` : ""}
                </p>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
