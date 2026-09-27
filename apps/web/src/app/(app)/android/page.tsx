"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";
import { Plus, RefreshCw, Smartphone, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

type Device = Schemas["AndroidDevice"];
type Policy = Schemas["AndroidPolicySettings"];
const KIND = { company: "Company phone", work_profile: "Work profile", unknown: "—" } as const;

/** Android Enterprise: Nexus as the EMM, through Google's Android Management API. */
export default function AndroidPage() {
  const can = useCan();
  const status = useQuery({ queryKey: ["android"], queryFn: () => unwrap(api.GET("/v1/android")) });
  const s = status.data;
  return (
    <>
      <PageHeader
        title="Android"
        description="Manage Android phones and tablets with Android Enterprise: company phones fully managed, personal ones with a work profile. Nexus sets their policy, enrolls them and sends commands through Google's Android Management API."
      />
      {status.isPending ? (
        <Skeleton className="h-40" />
      ) : !s ? (
        <ErrorBanner error={status.error} />
      ) : (
        <div className="space-y-5">
          {!s.enterprise ? <Connect status={s} canManage={can("org:manage")} /> : null}
          {s.enterprise ? (
            <>
              <PolicyCard policy={s.policy} appliedAt={s.policy_applied_at} canEdit={can("devices:enforce")} />
              <Devices lastSync={s.last_sync_at} lastError={s.last_error} />
            </>
          ) : null}
        </div>
      )}
    </>
  );
}

function Connect({ status, canManage }: { status: { service_account: string | null; project_id: string }; canManage: boolean }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [project, setProject] = useState(status.project_id);
  const [key, setKey] = useState("");
  const saveKey = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.PUT("/v1/android/service-account", { body: { project_id: project.trim(), key_json: key } }))),
    onSuccess: () => (setKey(""), qc.invalidateQueries({ queryKey: ["android"] }), toast.success("Service account saved")),
  });
  const signup = useMutation({ mutationFn: () => unwrap(api.POST("/v1/android/signup")), onSuccess: (r) => window.location.assign(r.url) });
  return (
    <Card>
      <CardHeader title="Connect Android Enterprise" description="Two steps: give Nexus a Google Cloud service account, then create your organization's Android enterprise with Google." />
      <div className="space-y-4 px-4 pb-4 text-[13px]">
        <ol className="list-decimal space-y-1 pl-5 text-fg-muted">
          <li>In Google Cloud, create a project and enable the Android Management API.</li>
          <li>Create a service account with the Android Management User role, and download a JSON key.</li>
        </ol>
        {canManage ? (
          <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), saveKey.mutate())}>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Google Cloud project ID" htmlFor="an-project">
                <Input id="an-project" value={project} onChange={(e) => setProject(e.target.value)} placeholder="acme-emm" />
              </Field>
              <Field label="Service account key (JSON file)" htmlFor="an-key" hint={status.service_account ? `Now: ${status.service_account}` : "Stored sealed."}>
                <Input id="an-key" type="file" accept="application/json,.json" onChange={async (e) => setKey((await e.target.files?.[0]?.text()) ?? "")} />
              </Field>
            </div>
            <ErrorBanner error={saveKey.error} />
            <Button type="submit" loading={saveKey.isPending} disabled={!project.trim() || !key}>
              Save service account
            </Button>
          </form>
        ) : (
          <p className="text-fg-muted">An owner or admin sets this up.</p>
        )}
        {status.service_account && canManage ? (
          <div className="space-y-2 border-t border-border pt-4">
            <p>Next, sign in to Google with the account that will own your Android enterprise (a Google Workspace or Gmail account). Google sends you back here when it&apos;s created.</p>
            <ErrorBanner error={signup.error} />
            <Button variant="primary" loading={signup.isPending} onClick={() => signup.mutate()}>
              Connect to Google
            </Button>
          </div>
        ) : null}
      </div>
    </Card>
  );
}

function PolicyCard({ policy, appliedAt, canEdit }: { policy: Policy; appliedAt: string | null; canEdit: boolean }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [p, setP] = useState(policy);
  const [app, setApp] = useState("");
  const save = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.PUT("/v1/android/policy", { body: p }))),
    onSuccess: () => (qc.invalidateQueries({ queryKey: ["android"] }), toast.success("Policy applied", { description: "Devices pick it up within minutes." })),
  });
  const dirty = JSON.stringify(p) !== JSON.stringify(policy);
  return (
    <Card>
      <CardHeader title="Policy" description={`Applied to every enrolled phone and tablet${appliedAt ? `, last ${timeAgo(appliedAt)}` : ""}.`} />
      <div className="space-y-3 px-4 pb-4 text-[13px]">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Passcode, minimum length" htmlFor="an-pw" hint="0: no passcode required">
            <Input id="an-pw" type="number" min={0} max={16} disabled={!canEdit} value={p.password_min_length} onChange={(e) => setP({ ...p, password_min_length: Number(e.target.value) })} />
          </Field>
          <Field label="Lock after (minutes idle)" htmlFor="an-lock">
            <Input id="an-lock" type="number" min={1} max={60} disabled={!canEdit} value={p.lock_after_minutes} onChange={(e) => setP({ ...p, lock_after_minutes: Number(e.target.value) })} />
          </Field>
        </div>
        <label className="flex items-center gap-2">
          <input type="checkbox" disabled={!canEdit} checked={p.block_unknown_sources} onChange={(e) => setP({ ...p, block_unknown_sources: e.target.checked })} /> Only apps from Google Play
        </label>
        <label className="flex items-center gap-2">
          <input type="checkbox" disabled={!canEdit} checked={p.disable_camera} onChange={(e) => setP({ ...p, disable_camera: e.target.checked })} /> Turn off the camera
        </label>
        <div>
          <p className="mb-1 font-medium">Apps</p>
          <ul className="mb-2 divide-y divide-border rounded-md border border-border">
            {p.apps.map((a, i) => (
              <li key={a.package} className="flex items-center gap-2 px-3 py-1.5">
                <code className="flex-1 font-mono text-xs">{a.package}</code>
                <Select disabled={!canEdit} value={a.install} onChange={(e) => setP({ ...p, apps: p.apps.map((x, j) => (j === i ? { ...x, install: e.target.value as typeof a.install } : x)) })} aria-label={`Install ${a.package}`}>
                  <option value="force">Install</option>
                  <option value="available">Available in Play</option>
                  <option value="blocked">Blocked</option>
                </Select>
                {canEdit ? (
                  <Button size="icon" variant="ghost" aria-label={`Remove ${a.package}`} onClick={() => setP({ ...p, apps: p.apps.filter((_, j) => j !== i) })}>
                    <Trash2 />
                  </Button>
                ) : null}
              </li>
            ))}
            {!p.apps.length ? <li className="px-3 py-1.5 text-fg-muted">No apps managed.</li> : null}
          </ul>
          {canEdit ? (
            <div className="flex gap-2">
              <Input className="max-w-xs font-mono text-xs" placeholder="com.slack" value={app} onChange={(e) => setApp(e.target.value.trim())} aria-label="Package name" />
              <Button size="sm" disabled={!app || p.apps.some((a) => a.package === app)} onClick={() => (setP({ ...p, apps: [...p.apps, { package: app, install: "force" }] }), setApp(""))}>
                <Plus /> Add app
              </Button>
            </div>
          ) : null}
        </div>
        <ErrorBanner error={save.error} />
        {canEdit ? (
          <Button variant="primary" loading={save.isPending} disabled={!dirty} onClick={() => save.mutate()}>
            Apply policy
          </Button>
        ) : null}
      </div>
    </Card>
  );
}

function Devices({ lastSync, lastError }: { lastSync: string | null; lastError: string }) {
  const can = useCan();
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["android-devices"], queryFn: () => unwrap(api.GET("/v1/android/devices")) });
  const [enrolling, setEnrolling] = useState(false);
  const [acting, setActing] = useState<{ device: Device; command: "lock" | "reboot" | "start_lost_mode" | "stop_lost_mode" | "remove" } | null>(null);
  const sync = useMutation({ mutationFn: () => unwrap(api.POST("/v1/android/sync")), onSuccess: () => (qc.invalidateQueries({ queryKey: ["android-devices"] }), qc.invalidateQueries({ queryKey: ["android"] })) });
  return (
    <Card className="overflow-hidden">
      <CardHeader
        title="Devices"
        description={lastSync ? `Checked with Google ${timeAgo(lastSync)} (every hour).` : "Not checked with Google yet."}
        actions={
          <div className="flex gap-2">
            <Button size="sm" loading={sync.isPending} onClick={() => sync.mutate()}>
              <RefreshCw /> Check now
            </Button>
            {can("devices:write") ? (
              <Button size="sm" variant="primary" onClick={() => setEnrolling(true)}>
                <Plus /> Enroll a device
              </Button>
            ) : null}
          </div>
        }
      />
      {lastError ? (
        <div className="px-4 pb-3">
          <ErrorBanner error={new Error(lastError)} />
        </div>
      ) : null}
      <ErrorBanner error={list.error ?? sync.error} />
      {!list.data?.data.length ? (
        <EmptyState icon={<Smartphone className="size-5" />} title="No devices yet" description="Enroll a company phone with a QR code, or add a work profile to a personal phone with a link." />
      ) : (
        <Table>
          <THead>
            <tr>
              <TH>Device</TH>
              <TH>Android</TH>
              <TH>Kind</TH>
              <TH>Policy</TH>
              <TH>Owner</TH>
              <TH>Last report</TH>
              <TH />
            </tr>
          </THead>
          <tbody>
            {list.data.data.map((d) => (
              <TR key={d.id}>
                <TD>
                  <p className="font-medium">{[d.brand, d.model].filter(Boolean).join(" ") || "Android device"}</p>
                  <p className="font-mono text-xs text-fg-muted">{d.serial || "—"}</p>
                </TD>
                <TD className="text-fg-muted">
                  {d.android_version || "—"}
                  {d.security_patch ? <span className="block text-xs">patch {d.security_patch}</span> : null}
                </TD>
                <TD>{KIND[d.kind]}</TD>
                <TD>
                  {d.policy_compliant === null ? (
                    "—"
                  ) : d.policy_compliant ? (
                    <StatusPill tone="success">Compliant</StatusPill>
                  ) : (
                    <span title={d.non_compliance.map((n) => `${n.setting}: ${n.reason}`).join("\n")}>
                      <StatusPill tone="warning">Not compliant</StatusPill>
                    </span>
                  )}
                  {d.state && d.state !== "ACTIVE" ? <span className="ml-1.5 text-xs text-fg-muted">{d.state.toLowerCase()}</span> : null}
                </TD>
                <TD className="text-fg-muted">{d.assigned_user?.email ?? "—"}</TD>
                <TD className="text-fg-muted">{d.last_status_at ? timeAgo(d.last_status_at) : "—"}</TD>
                <TD className="text-right">
                  {can("devices:actions") ? (
                    <Select aria-label="Actions" value="" onChange={(e) => e.target.value && setActing({ device: d, command: e.target.value as never })}>
                      <option value="">Actions…</option>
                      <option value="lock">Lock</option>
                      {d.kind === "company" ? (
                        <>
                          <option value="reboot">Reboot</option>
                          <option value="start_lost_mode">Turn on Lost Mode</option>
                          <option value="stop_lost_mode">Turn off Lost Mode</option>
                        </>
                      ) : null}
                      {can("devices:wipe") ? <option value="remove">{d.kind === "work_profile" ? "Remove work profile" : "Erase"}</option> : null}
                    </Select>
                  ) : null}
                </TD>
              </TR>
            ))}
          </tbody>
        </Table>
      )}
      {enrolling ? <EnrollDialog onClose={() => setEnrolling(false)} /> : null}
      {acting ? <CommandDialog device={acting.device} command={acting.command} onClose={() => setActing(null)} /> : null}
    </Card>
  );
}

function EnrollDialog({ onClose }: { onClose: () => void }) {
  const [kind, setKind] = useState<"company" | "work_profile">("company");
  const [q, setQ] = useState("");
  const [userId, setUserId] = useState<string | null>(null);
  const users = useQuery({ queryKey: ["users", "picker", q], enabled: q.length > 1 && !userId, queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { q, limit: 6, status: "active" } } })) });
  const make = useMutation({ mutationFn: () => unwrap(api.POST("/v1/android/enrollment-tokens", { body: { kind, user_id: userId, days: 7 } })) });
  const t = make.data;
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Enroll an Android device" className="max-w-lg">
        {t ? (
          kind === "company" ? (
            <div className="space-y-3 text-[13px]">
              <p>On a new or factory-reset phone, tap the welcome screen six times, connect to Wi-Fi, and scan this code.</p>
              <div className="flex justify-center rounded-md bg-white p-3">
                <QRCodeSVG value={t.qr_code} size={220} />
              </div>
              <p className="text-xs text-fg-muted">Valid until {new Date(t.expires_at).toLocaleDateString()}. Or type the code during setup: {t.value}</p>
            </div>
          ) : (
            <div className="space-y-3 text-[13px]">
              <p>Send this link to the person. On their phone, it adds a work profile: work apps are kept apart, and Nexus can&apos;t see or erase their personal data.</p>
              <CopyField label="Enrollment link" value={t.enroll_url} />
              <p className="text-xs text-fg-muted">Valid until {new Date(t.expires_at).toLocaleDateString()}.</p>
            </div>
          )
        ) : (
          <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), make.mutate())}>
            <Field label="Kind" htmlFor="en-kind">
              <Select id="en-kind" className="w-full" value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
                <option value="company">Company phone (fully managed, QR code)</option>
                <option value="work_profile">Personal phone (work profile, link)</option>
              </Select>
            </Field>
            <Field label="Whose device (optional)" htmlFor="en-user">
              <Input id="en-user" placeholder="Search people" value={q} onChange={(e) => (setQ(e.target.value), setUserId(null))} />
              <ul className="divide-y divide-border">
                {users.data?.data.map((u) => (
                  <li key={u.id}>
                    <button type="button" className="w-full py-1.5 text-left text-[13px] hover:underline" onClick={() => (setUserId(u.id), setQ(u.email))}>
                      {u.display_name || u.email}
                    </button>
                  </li>
                ))}
              </ul>
            </Field>
            <ErrorBanner error={make.error} />
            <Button type="submit" variant="primary" loading={make.isPending}>
              Make enrollment {kind === "company" ? "QR code" : "link"}
            </Button>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function CommandDialog({ device, command, onClose }: { device: Device; command: "lock" | "reboot" | "start_lost_mode" | "stop_lost_mode" | "remove"; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  const [phone, setPhone] = useState("");
  const [confirm, setConfirm] = useState("");
  const name = [device.brand, device.model].filter(Boolean).join(" ") || "this device";
  const label = { lock: "Lock", reboot: "Reboot", start_lost_mode: "Turn on Lost Mode", stop_lost_mode: "Turn off Lost Mode", remove: device.kind === "work_profile" ? "Remove work profile" : "Erase" }[command];
  const go = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        command === "remove"
          ? unwrap(api.DELETE("/v1/android/devices/{id}", { params: { path: { id: device.id } }, body: { reason, confirm } }))
          : unwrap(api.POST("/v1/android/devices/{id}/commands", { params: { path: { id: device.id } }, body: { command, reason, ...(message ? { message } : {}), ...(phone ? { phone } : {}) } })),
      ),
    onSuccess: () => (qc.invalidateQueries({ queryKey: ["android-devices"] }), toast.success(`${label}: sent to ${name}`), onClose()),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        title={`${label}: ${name}`}
        description={command === "remove" ? (device.kind === "work_profile" ? "Removes the work profile and its apps and data. Their personal data stays." : "Erases everything on the phone. This can't be undone.") : "Sent through Google; the device acts on it when it's online."}
      >
        <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), go.mutate())}>
          <Field label="Reason" htmlFor="ac-reason" hint="Saved to the audit log.">
            <Input id="ac-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
          </Field>
          {command === "start_lost_mode" ? (
            <>
              <Field label="Message on the screen" htmlFor="ac-msg">
                <Input id="ac-msg" value={message} onChange={(e) => setMessage(e.target.value)} placeholder="This phone belongs to Acme. Please call IT." />
              </Field>
              <Field label="Phone number to show" htmlFor="ac-phone">
                <Input id="ac-phone" value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+1 555 0100" />
              </Field>
            </>
          ) : null}
          {command === "remove" ? (
            <Field label={`Type the serial number (${device.serial}) to confirm`} htmlFor="ac-confirm">
              <Input id="ac-confirm" className="font-mono" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </Field>
          ) : null}
          <ErrorBanner error={go.error} />
          <Button type="submit" variant={command === "remove" || command === "start_lost_mode" ? "danger" : "primary"} loading={go.isPending} disabled={reason.trim().length < 3 || (command === "remove" && confirm.trim() !== device.serial)}>
            {label}
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}
