"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, Lock, Power, RefreshCw, ShieldOff } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/features/confirm-action";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { EmptyState, StatusPill, type Tone } from "@/components/ui/misc";
import { Dialog, DialogContent, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime, timeAgo } from "@/lib/utils";

type Device = Schemas["DeviceDetail"];
type Command = Schemas["DeviceCommand"];
type Action = Exclude<Command["action"], "osquery">; // live queries have their own page

const LABEL: Record<Action, string> = { refresh: "Refresh", lock: "Lock", restart: "Restart", wipe: "Wipe" };

/** Device actions (DEV-09): refresh, lock, restart, wipe, each confirmed and audited. */
export function DeviceActions({ device: d }: { device: Device }) {
  const qc = useQueryClient();
  const can = useCan();
  const withStepUp = useStepUp();
  const [confirm, setConfirm] = useState<Exclude<Action, "refresh"> | null>(null);
  const [pin, setPin] = useState<string | null>(null);
  const managed = d.mdm.some((m) => m.managed);
  const run = async (action: Action, reason = "") => {
    const r = await withStepUp(() => unwrap(api.POST("/v1/devices/{id}/actions", { params: { path: { id: d.id } }, body: { action, reason, ...(action === "wipe" ? { confirm: d.hostname } : {}) } })));
    qc.invalidateQueries({ queryKey: ["device-commands", d.id] });
    const via = r.command.channel === "mdm" ? `through ${d.mdm[0]?.source ?? "your MDM"}` : d.online ? "the device picks it up within a minute" : "the device picks it up when it's next online";
    toast.success(action === "refresh" ? `Asked ${d.hostname} to report now` : `${LABEL[action]} requested`, { description: via });
    if (r.unlock_pin) setPin(r.unlock_pin);
    return r;
  };
  const refresh = useMutation({ mutationFn: () => run("refresh") });
  if (!can("devices:actions")) return null;

  const effects: Record<Exclude<Action, "refresh">, string[]> = {
    lock: managed
      ? [`${d.mdm[0]!.source} locks ${d.hostname} now.`, d.mdm[0]!.source === "Jamf Pro" ? "You'll get a 6-digit PIN to unlock it: pass it to the user." : "The user signs in again to unlock."]
      : [`The Nexus agent locks the screen the next time ${d.hostname} checks in (about a minute if it's online).`, "Nothing open is lost; the user signs in again."],
    restart: [`${d.hostname} restarts in about a minute.`, "Unsaved work in open apps may be lost: tell the user first if you can."],
    wipe: [`${d.mdm[0]?.source ?? "Your MDM"} erases ${d.hostname}: every file and app on it.`, "This can't be undone, and the device leaves Nexus when it's erased."],
  };
  return (
    <>
      <Menu>
        <MenuTrigger asChild>
          <Button>
            Actions <ChevronDown />
          </Button>
        </MenuTrigger>
        <MenuContent>
          <MenuItem onSelect={() => refresh.mutate()}>
            <RefreshCw className="size-4" /> Refresh now
          </MenuItem>
          <MenuItem onSelect={() => setConfirm("lock")}>
            <Lock className="size-4" /> Lock
          </MenuItem>
          <MenuItem onSelect={() => setConfirm("restart")}>
            <Power className="size-4" /> Restart
          </MenuItem>
          {can("devices:wipe") ? (
            <>
              <MenuSeparator />
              <MenuItem danger disabled={!managed} onSelect={() => setConfirm("wipe")}>
                <ShieldOff className="size-4" /> Wipe{managed ? "" : " (needs an MDM)"}
              </MenuItem>
            </>
          ) : null}
        </MenuContent>
      </Menu>
      {confirm ? (
        <ConfirmAction
          open
          onOpenChange={(o) => !o && setConfirm(null)}
          title={`${LABEL[confirm]} ${d.hostname}?`}
          effects={effects[confirm]}
          confirmLabel={`${LABEL[confirm]} ${d.hostname}`}
          danger={confirm === "wipe"}
          typeToConfirm={confirm === "wipe" ? d.hostname : undefined}
          onConfirm={(reason) => run(confirm, reason)}
        />
      ) : null}
      {pin ? (
        <Dialog open onOpenChange={(o) => !o && setPin(null)}>
          <DialogContent title="Unlock PIN" description={`${d.hostname} will ask for this PIN. It's shown only now: give it to the user when they should get back in.`}>
            <CopyField value={pin} />
            <div className="mt-4 flex justify-end">
              <Button variant="primary" onClick={() => setPin(null)}>
                Done
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  );
}

const TONE: Record<Command["status"], { label: string; tone: Tone }> = {
  queued: { label: "Waiting for the device", tone: "neutral" },
  sent: { label: "Sent", tone: "primary" },
  done: { label: "Done", tone: "success" },
  failed: { label: "Failed", tone: "danger" },
  expired: { label: "Expired", tone: "neutral" },
  canceled: { label: "Canceled", tone: "neutral" },
};

export function CommandHistory({ deviceId }: { deviceId: string }) {
  const qc = useQueryClient();
  const can = useCan();
  const list = useQuery({
    queryKey: ["device-commands", deviceId],
    queryFn: () => unwrap(api.GET("/v1/devices/{id}/commands", { params: { path: { id: deviceId } } })),
    refetchInterval: (q) => (q.state.data?.data.some((c) => c.status === "queued" || c.status === "sent") ? 3000 : 30_000),
  });
  const cancel = useMutation({
    mutationFn: (cid: string) => unwrap(api.POST("/v1/devices/{id}/commands/{command_id}/cancel", { params: { path: { id: deviceId, command_id: cid } } })),
    onSuccess: (r) => qc.setQueryData(["device-commands", deviceId], r),
  });
  if (!list.data?.data.length) return <EmptyState title="No actions yet" description="Refresh, lock, restart or wipe this device from the Actions menu." />;
  return (
    <ul className="divide-y divide-border">
      {list.data.data.map((c) => (
        <li key={c.id} className="flex flex-wrap items-start gap-3 px-4 py-3 text-[13px]">
          <div className="min-w-0 flex-1">
            <p className="flex flex-wrap items-center gap-2 font-medium">
              {c.action === "osquery" ? "Live query" : LABEL[c.action]} <StatusPill tone={TONE[c.status].tone}>{TONE[c.status].label}</StatusPill>
              <span className="text-xs font-normal text-fg-muted">{c.channel === "mdm" ? "via MDM" : "via the Nexus agent"}</span>
            </p>
            <p className="text-xs text-fg-muted">
              {c.requested_by ?? "Someone"} · {timeAgo(c.created_at)}
              {c.reason ? ` · “${c.reason}”` : ""}
            </p>
            {c.output ? <p className="mt-1 text-xs text-fg-subtle">{c.output}</p> : null}
            {c.finished_at ? <p className="text-[11px] text-fg-subtle">Finished {formatDateTime(c.finished_at)}</p> : null}
          </div>
          {c.status === "queued" && can("devices:actions") ? (
            <Button size="sm" variant="ghost" loading={cancel.isPending} onClick={() => cancel.mutate(c.id)}>
              Cancel
            </Button>
          ) : null}
        </li>
      ))}
    </ul>
  );
}
