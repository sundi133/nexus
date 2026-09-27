"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Apple, CheckCircle2, Link2, Plus, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { AdeCard } from "@/components/features/ade-card";
import { MdmProfiles } from "@/components/features/mdm-profiles";
import { CopyField } from "@/components/ui/copy";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime, timeAgo } from "@/lib/utils";

type Mac = Schemas["AppleMdmDevice"];
type RequestType =
  | "DeviceInformation"
  | "SecurityInfo"
  | "InstalledApplicationList"
  | "ProfileList"
  | "DeviceLock"
  | "RestartDevice"
  | "ShutDownDevice"
  | "ScheduleOSUpdate"
  | "EraseDevice"
  | "ClearPasscode"
  | "EnableLostMode"
  | "PlayLostModeSound"
  | "DeviceLocation"
  | "DisableLostMode";
type Platform = Mac["platform"];
type Perm = Parameters<ReturnType<typeof useCan>>[0];
const ALL: Platform[] = ["macos", "ios", "ipados"];
const MOBILE: Platform[] = ["ios", "ipados"];
/** What can be sent to which kind of device (Lost Mode and clearing a passcode are iPhone and iPad only). */
const ACTIONS: { type: RequestType; label: string; perm: Perm; platforms: Platform[]; danger?: boolean; lost?: boolean }[] = [
  { type: "DeviceInformation", label: "Refresh details", perm: "devices:read", platforms: ALL },
  { type: "SecurityInfo", label: "Refresh security info", perm: "devices:read", platforms: ALL },
  { type: "InstalledApplicationList", label: "List installed apps", perm: "devices:read", platforms: ALL },
  { type: "ScheduleOSUpdate", label: "Install OS updates", perm: "devices:updates", platforms: ALL },
  { type: "RestartDevice", label: "Restart", perm: "devices:actions", platforms: ALL },
  { type: "DeviceLock", label: "Lock", perm: "devices:actions", platforms: ALL, danger: true },
  { type: "ClearPasscode", label: "Clear passcode", perm: "devices:actions", platforms: MOBILE, danger: true },
  { type: "EnableLostMode", label: "Turn on Lost Mode", perm: "devices:actions", platforms: MOBILE, danger: true, lost: false },
  { type: "DeviceLocation", label: "Locate", perm: "devices:actions", platforms: MOBILE, lost: true },
  { type: "PlayLostModeSound", label: "Play a sound", perm: "devices:actions", platforms: MOBILE, lost: true },
  { type: "DisableLostMode", label: "Turn off Lost Mode", perm: "devices:actions", platforms: MOBILE, lost: true },
  { type: "EraseDevice", label: "Erase", perm: "devices:wipe", platforms: ALL, danger: true },
];
const KIND: Record<Platform, string> = { macos: "Mac", ios: "iPhone", ipados: "iPad", other: "Device" };

const STATUS: Record<Mac["status"], { label: string; tone: "success" | "neutral" | "warning" }> = {
  enrolled: { label: "enrolled", tone: "success" },
  authenticated: { label: "enrolling", tone: "warning" },
  checked_out: { label: "removed", tone: "neutral" },
};

export default function AppleMdmPage() {
  const can = useCan();
  const status = useQuery({ queryKey: ["apple-mdm"], queryFn: () => unwrap(api.GET("/v1/apple-mdm")) });
  const devices = useQuery({ queryKey: ["apple-mdm-devices"], queryFn: () => unwrap(api.GET("/v1/apple-mdm/devices")), refetchInterval: 20_000 });
  const [acting, setActing] = useState<{ mac: Mac; type: RequestType } | null>(null);
  const [history, setHistory] = useState<Mac | null>(null);
  const [owning, setOwning] = useState<Mac | null>(null);
  const s = status.data;
  return (
    <>
      <PageHeader
        title="Apple MDM"
        description="Nexus as the device management server for your Macs, iPhones and iPads: enroll them with a profile, push configuration profiles, and lock, erase, restart and update them. On iPhones and iPads, also clear a forgotten passcode and use Lost Mode. Works alongside the Nexus agent on the same Mac (matched by serial number)."
      />
      {status.isPending ? (
        <Skeleton className="h-40" />
      ) : !s ? (
        <ErrorBanner error={status.error} />
      ) : (
        <div className="space-y-5">
          <PushSetup ready={s.ready} csrPending={s.csr_pending} push={s.push} canManage={can("org:manage")} />
          {s.ready ? <EnrollLinks canManage={can("devices:write")} /> : null}
          {s.ready ? <AdeCard /> : null}
          {s.ready ? <MdmProfiles /> : null}
          <Card className="overflow-hidden">
            <CardHeader title="Enrolled devices" description={`${s.devices.enrolled} enrolled`} />
            {devices.data?.data.length ? (
              <Table>
                <THead>
                  <tr>
                    <TH>Device</TH>
                    <TH>OS</TH>
                    <TH>Status</TH>
                    <TH>Security</TH>
                    <TH>Last check-in</TH>
                    <TH />
                  </tr>
                </THead>
                <tbody>
                  {devices.data.data.map((d) => (
                    <TR key={d.id}>
                      <TD>
                        <button type="button" className="text-left font-medium hover:underline" onClick={() => setHistory(d)}>
                          {d.device_name || d.serial || KIND[d.platform]}
                        </button>
                        <span className="block text-xs text-fg-muted">
                          {KIND[d.platform]} · {d.model} · {d.serial}
                          {d.platform !== "macos" ? (
                            <>
                              {" · "}
                              {can("devices:write") ? (
                                <button type="button" className="hover:underline" onClick={() => setOwning(d)}>
                                  {d.assigned_user ? d.assigned_user.email : "assign to someone"}
                                </button>
                              ) : (
                                (d.assigned_user?.email ?? "unassigned")
                              )}
                            </>
                          ) : null}
                          {d.device_id ? (
                            <>
                              {" · "}
                              <Link href={`/devices/${d.device_id}`} className="hover:underline">
                                agent
                              </Link>
                            </>
                          ) : null}
                        </span>
                      </TD>
                      <TD className="text-fg-muted">{d.os_version || "—"}</TD>
                      <TD>
                        <StatusPill tone={STATUS[d.status].tone}>{STATUS[d.status].label}</StatusPill>
                        {d.pending_commands ? <span className="ml-1.5 text-xs text-fg-muted">{d.pending_commands} pending</span> : null}
                      </TD>
                      <TD className="text-xs text-fg-muted">
                        {d.platform === "macos" ? (
                          <>
                            {d.filevault === null ? "—" : d.filevault ? "FileVault on" : "FileVault off"}
                            {d.bootstrap_token ? " · bootstrap token" : ""}
                          </>
                        ) : (
                          <>
                            {d.passcode === null ? "—" : d.passcode ? "Passcode set" : "No passcode"}
                            {d.supervised ? " · supervised" : ""}
                          </>
                        )}
                        {d.lost_mode ? (
                          <span className="ml-1.5">
                            <StatusPill tone="danger">Lost Mode</StatusPill>
                          </span>
                        ) : null}
                      </TD>
                      <TD className="text-fg-muted">{d.last_seen_at ? timeAgo(d.last_seen_at) : "—"}</TD>
                      <TD className="text-right">
                        {d.status === "enrolled" ? (
                          <Select
                            aria-label={`Actions for ${d.device_name || d.serial}`}
                            value=""
                            onChange={(e) => e.target.value && setActing({ mac: d, type: e.target.value as RequestType })}
                          >
                            <option value="">Actions…</option>
                            {ACTIONS.filter((a) => can(a.perm) && a.platforms.includes(d.platform) && (a.lost === undefined || a.lost === d.lost_mode)).map((a) => (
                              <option key={a.type} value={a.type}>
                                {a.label}
                              </option>
                            ))}
                          </Select>
                        ) : null}
                      </TD>
                    </TR>
                  ))}
                </tbody>
              </Table>
            ) : (
              <EmptyState
                icon={<Apple className="size-5" />}
                title="No devices enrolled yet"
                description={s.ready ? "Open an enrollment link on a Mac (then System Settings), or in Safari on an iPhone or iPad (then Settings → Profile Downloaded), and install the profile." : "Set up the push certificate first."}
              />
            )}
          </Card>
        </div>
      )}
      {acting ? <CommandDialog mac={acting.mac} type={acting.type} onClose={() => setActing(null)} /> : null}
      {history ? <HistoryDialog mac={history} onClose={() => setHistory(null)} /> : null}
      {owning ? <OwnerDialog device={owning} onClose={() => setOwning(null)} /> : null}
    </>
  );
}

function PushSetup({ ready, csrPending, push, canManage }: { ready: boolean; csrPending: boolean; push: { topic: string; expires_at: string } | null; canManage: boolean }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [csr, setCsr] = useState<string | null>(null);
  const [pem, setPem] = useState("");
  const makeCsr = useMutation({ mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/apple-mdm/push-csr"))), onSuccess: (r) => (setCsr(r.csr), qc.invalidateQueries({ queryKey: ["apple-mdm"] })) });
  const upload = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.PUT("/v1/apple-mdm/push-cert", { body: { certificate: pem.trim() } }))),
    onSuccess: () => (toast.success("Push certificate saved", { description: "Macs can enroll now." }), setPem(""), setCsr(null), qc.invalidateQueries({ queryKey: ["apple-mdm"] })),
  });
  const soon = push && new Date(push.expires_at).getTime() - Date.now() < 30 * 86_400_000;
  return (
    <Card>
      <CardHeader
        title="Apple push certificate"
        description={
          ready && push ? (
            <span className="flex flex-wrap items-center gap-2">
              <CheckCircle2 className="size-4 text-success" /> In place until {formatDateTime(push.expires_at)} · <code className="font-mono text-xs">{push.topic}</code>
              {soon ? <StatusPill tone="warning">renew soon</StatusPill> : null}
            </span>
          ) : (
            "Apple wakes enrolled Macs through its push service, with a certificate issued to your organization. It's free, and renewed yearly."
          )
        }
      />
      {canManage ? (
        <div className="space-y-3 px-4 pb-4 text-[13px]">
          {!ready || csrPending || csr ? (
            <ol className="list-decimal space-y-3 pl-5">
              <li>
                Make Nexus's certificate request.{" "}
                <Button size="sm" loading={makeCsr.isPending} onClick={() => makeCsr.mutate()}>
                  {csrPending || csr ? "Make a new one" : "Make the request (CSR)"}
                </Button>
                {csr ? <textarea readOnly aria-label="Certificate request" className="mt-2 h-28 w-full rounded-md border border-border bg-bg-subtle p-2 font-mono text-[11px]" value={csr} /> : null}
              </li>
              <li>Have it signed by an MDM vendor certificate (Apple Developer Enterprise program, or your MDM vendor&apos;s signing service), then upload the signed request at Apple&apos;s Push Certificates Portal (identity.apple.com/pushcert) with a company Apple Account. For a renewal, choose Renew on the existing certificate.</li>
              <li>
                Paste the certificate Apple gives you (PEM):
                <textarea aria-label="Apple push certificate" className="mt-2 h-28 w-full rounded-md border border-border bg-bg p-2 font-mono text-[11px]" placeholder="-----BEGIN CERTIFICATE-----" value={pem} onChange={(e) => setPem(e.target.value)} />
                <Button className="mt-2" variant="primary" size="sm" loading={upload.isPending} disabled={pem.trim().length < 100} onClick={() => upload.mutate()}>
                  Save certificate
                </Button>
              </li>
            </ol>
          ) : (
            <Button size="sm" onClick={() => makeCsr.mutate()} loading={makeCsr.isPending}>
              Renew certificate
            </Button>
          )}
          <ErrorBanner error={makeCsr.error ?? upload.error} />
        </div>
      ) : null}
    </Card>
  );
}

function EnrollLinks({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const links = useQuery({ queryKey: ["apple-mdm-links"], queryFn: () => unwrap(api.GET("/v1/apple-mdm/enrollment-links")), enabled: canManage });
  const [name, setName] = useState("");
  const [days, setDays] = useState(30);
  const [made, setMade] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/apple-mdm/enrollment-links", { body: { name: name.trim(), expires_in_days: days } }))),
    onSuccess: (r) => (setMade(r.url), setName(""), qc.invalidateQueries({ queryKey: ["apple-mdm-links"] })),
  });
  const revoke = useMutation({ mutationFn: (id: string) => unwrap(api.DELETE("/v1/apple-mdm/enrollment-links/{id}", { params: { path: { id } } })), onSuccess: () => qc.invalidateQueries({ queryKey: ["apple-mdm-links"] }) });
  if (!canManage) return null;
  return (
    <Card>
      <CardHeader title="Enrollment links" description="Open a link on a Mac: it downloads a profile with the Mac's own identity. Installing it in System Settings → Privacy & Security → Profiles enrolls the Mac." />
      <div className="space-y-3 px-4 pb-4">
        <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => (e.preventDefault(), create.mutate())}>
          <Field label="Name" htmlFor="ml-name">
            <Input id="ml-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Office Macs" />
          </Field>
          <Field label="Works for" htmlFor="ml-days">
            <Select id="ml-days" value={String(days)} onChange={(e) => setDays(Number(e.target.value))}>
              {[1, 7, 30, 90, 365].map((d) => (
                <option key={d} value={d}>
                  {d === 1 ? "1 day" : `${d} days`}
                </option>
              ))}
            </Select>
          </Field>
          <Button type="submit" loading={create.isPending} disabled={!name.trim()}>
            <Plus className="size-3.5" /> Make link
          </Button>
        </form>
        <ErrorBanner error={create.error} />
        {made ? (
          <div className="space-y-1 rounded-md border border-border p-3 text-[13px]">
            <p className="flex items-center gap-1.5 font-medium">
              <Link2 className="size-4" /> Shown only now. Anyone with it can enroll a Mac into your organization.
            </p>
            <CopyField value={made} />
          </div>
        ) : null}
        {links.data?.data.length ? (
          <ul className="divide-y divide-border rounded-md border border-border text-[13px]">
            {links.data.data.map((l) => (
              <li key={l.id} className="flex items-center justify-between px-3 py-1.5">
                <span>
                  {l.name} <span className="text-xs text-fg-muted">· used {l.uses} times · {l.revoked ? "inactive" : `until ${formatDateTime(l.expires_at)}`}</span>
                </span>
                {!l.revoked ? (
                  <Button size="sm" variant="ghost" onClick={() => revoke.mutate(l.id)}>
                    Revoke
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </Card>
  );
}

function CommandDialog({ mac, type, onClose }: { mac: Mac; type: RequestType; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const action = ACTIONS.find((a) => a.type === type)!;
  const readOnly = action.perm === "devices:read";
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  const [phone, setPhone] = useState("");
  const [confirm, setConfirm] = useState("");
  const kind = KIND[mac.platform];
  const onScreen = type === "EnableLostMode" || type === "DeviceLock";
  const withPhone = mac.platform !== "macos" && (type === "DeviceLock" || type === "EnableLostMode");
  const [pin, setPin] = useState<string | null>(null);
  const send = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.POST("/v1/apple-mdm/devices/{id}/commands", {
            params: { path: { id: mac.id } },
            body: { request_type: type, reason, ...(onScreen && message ? { message } : {}), ...(withPhone && phone ? { phone } : {}), ...(type === "EraseDevice" ? { confirm } : {}) },
          }),
        ),
      ),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["apple-mdm-devices"] });
      if (r.push_error) toast.warning(`Queued, but the ${kind} couldn't be woken`, { description: `${r.push_error}. It runs the next time the ${kind} checks in.` });
      else toast.success(`${action.label}: sent to ${mac.device_name || mac.serial}`);
      if (r.pin) setPin(r.pin);
      else onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        title={`${action.label}: ${mac.device_name || mac.serial}`}
        description={
          type === "EraseDevice"
            ? `Erases everything on this ${kind}. This can't be undone.`
            : type === "EnableLostMode"
              ? "Locks it and shows your message and number. Only in Lost Mode can Nexus locate it. Needs a supervised iPhone or iPad."
              : type === "ClearPasscode"
                ? "Removes the passcode, so the person can open it and set a new one. Use it only once you've confirmed who's asking."
                : readOnly
                  ? `The ${kind} answers at its next check-in.`
                  : `Sent through MDM; the ${kind} acts on it right away if it's online.`
        }
      >
        {pin ? (
          <div className="space-y-2 text-[13px]">
            <p className="flex items-center gap-1.5">
              <ShieldCheck className="size-4 text-success" /> The {kind} will ask for this PIN. It&apos;s shown only now.
            </p>
            <p className="text-center font-mono text-3xl tracking-[0.3em]">{pin}</p>
            <div className="flex justify-end">
              <Button variant="primary" onClick={onClose}>
                Done
              </Button>
            </div>
          </div>
        ) : (
          <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), send.mutate())}>
            <ErrorBanner error={send.error} />
            {!readOnly ? (
              <Field label="Reason" htmlFor="mc-reason" hint="Saved to the audit log.">
                <Input id="mc-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
              </Field>
            ) : null}
            {onScreen ? (
              <Field label="Message on the lock screen" htmlFor="mc-msg">
                <Input id="mc-msg" value={message} onChange={(e) => setMessage(e.target.value)} placeholder="e.g. Please call IT at 555-0100" />
              </Field>
            ) : null}
            {withPhone ? (
              <Field label="Phone number to show" htmlFor="mc-phone">
                <Input id="mc-phone" value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+1 555 0100" />
              </Field>
            ) : null}
            {type === "EraseDevice" ? (
              <Field label={`Type the serial number (${mac.serial}) to confirm`} htmlFor="mc-confirm">
                <Input id="mc-confirm" className="font-mono" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
              </Field>
            ) : null}
            <div className="flex justify-end gap-2">
              <Button type="button" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" variant={action.danger ? "danger" : "primary"} loading={send.isPending} disabled={(!readOnly && reason.trim().length < 3) || (type === "EraseDevice" && confirm.trim() !== mac.serial)}>
                {action.label}
              </Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function HistoryDialog({ mac, onClose }: { mac: Mac; onClose: () => void }) {
  const q = useQuery({ queryKey: ["apple-mdm-commands", mac.id], queryFn: () => unwrap(api.GET("/v1/apple-mdm/devices/{id}/commands", { params: { path: { id: mac.id } } })), refetchInterval: 10_000 });
  const tone = (s: string) => (s === "acknowledged" ? "success" : s === "error" ? "danger" : s === "canceled" ? "neutral" : "warning") as "success" | "danger" | "neutral" | "warning";
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={mac.device_name || mac.serial} description={`${KIND[mac.platform]} · ${mac.model} · ${mac.serial} · ${mac.platform === "macos" ? "macOS" : mac.platform === "ipados" ? "iPadOS" : "iOS"} ${mac.os_version}`} className="max-w-2xl">
        <ul className="max-h-[60vh] divide-y divide-border overflow-y-auto rounded-md border border-border text-[13px]">
          {q.data?.data.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-1.5">
              <span>
                <span className="font-medium">{c.request_type}</span>
                <span className="block text-xs text-fg-muted">
                  {c.requested_by ?? "Nexus"} · {timeAgo(c.created_at)}
                  {c.reason ? ` · ${c.reason}` : ""}
                  {c.error ? ` · ${c.error}` : ""}
                </span>
                {c.request_type === "DeviceLocation" && c.status === "acknowledged" && (c.result as { Latitude?: number })?.Latitude !== undefined ? (
                  <a
                    className="block text-xs text-primary hover:underline"
                    target="_blank"
                    rel="noopener noreferrer"
                    href={`https://www.openstreetmap.org/?mlat=${(c.result as { Latitude: number }).Latitude}&mlon=${(c.result as { Longitude: number }).Longitude}#map=16/${(c.result as { Latitude: number }).Latitude}/${(c.result as { Longitude: number }).Longitude}`}
                  >
                    {(c.result as { Latitude: number }).Latitude.toFixed(5)}, {(c.result as { Longitude: number }).Longitude.toFixed(5)} · open map
                  </a>
                ) : null}
              </span>
              <StatusPill tone={tone(c.status)}>{c.status}</StatusPill>
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  );
}

/** Whose iPhone or iPad this is: profiles for their groups follow it. */
function OwnerDialog({ device, onClose }: { device: Mac; onClose: () => void }) {
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const users = useQuery({ queryKey: ["users", "picker", q], enabled: q.length > 1, queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { q, limit: 8, status: "active" } } })) });
  const save = useMutation({
    mutationFn: (userId: string | null) => unwrap(api.PUT("/v1/apple-mdm/devices/{id}/user", { params: { path: { id: device.id } }, body: { user_id: userId } })),
    onSuccess: () => (qc.invalidateQueries({ queryKey: ["apple-mdm-devices"] }), onClose()),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={`Whose is ${device.device_name || device.serial}?`} description="Profiles targeted at their groups are installed on it.">
        <div className="space-y-2">
          <Input autoFocus placeholder="Search people" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Person" />
          <ErrorBanner error={save.error} />
          <ul className="divide-y divide-border text-[13px]">
            {users.data?.data.map((u) => (
              <li key={u.id} className="flex items-center justify-between py-1.5">
                <span>{u.display_name || u.email}</span>
                <Button size="sm" loading={save.isPending} onClick={() => save.mutate(u.id)}>
                  Assign
                </Button>
              </li>
            ))}
          </ul>
          {device.assigned_user ? (
            <Button size="sm" variant="ghost" onClick={() => save.mutate(null)}>
              Clear (now {device.assigned_user.email})
            </Button>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}
