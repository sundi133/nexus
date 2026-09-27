"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileCog, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";

type Kind = "passcode" | "screen_lock" | "firewall" | "wifi" | "software_update" | "login_message" | "upload";
type Platform = "macos" | "ios" | "ipados";
const KINDS: { kind: Kind; label: string; where: string }[] = [
  { kind: "passcode", label: "Passcode", where: "Mac, iPhone, iPad" },
  { kind: "wifi", label: "Wi-Fi network", where: "Mac, iPhone, iPad" },
  { kind: "screen_lock", label: "Screen lock", where: "Mac" },
  { kind: "firewall", label: "Firewall", where: "Mac" },
  { kind: "software_update", label: "Automatic macOS updates", where: "Mac" },
  { kind: "login_message", label: "Login window message", where: "Mac" },
  { kind: "upload", label: "Upload a .mobileconfig", where: "you choose" },
];
const PLATFORM_LABEL: Record<Platform, string> = { macos: "Mac", ios: "iPhone", ipados: "iPad" };

/** Configuration profiles pushed to Macs, iPhones and iPads in Nexus MDM. */
export function MdmProfiles() {
  const can = useCan();
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const list = useQuery({ queryKey: ["apple-mdm-profiles"], queryFn: () => unwrap(api.GET("/v1/apple-mdm/profiles")), refetchInterval: 20_000 });
  const groups = useQuery({ queryKey: ["groups", {}], queryFn: () => unwrap(api.GET("/v1/groups")) });
  const [adding, setAdding] = useState(false);
  const del = useMutation({
    mutationFn: (id: string) => withStepUp(() => unwrap(api.DELETE("/v1/apple-mdm/profiles/{id}", { params: { path: { id } } }))),
    onSuccess: () => (toast.success("Deleted", { description: "It's being removed from the devices that have it." }), qc.invalidateQueries({ queryKey: ["apple-mdm-profiles"] })),
  });
  const groupName = (id: string) => groups.data?.data.find((g) => g.id === id)?.name ?? "a group";
  return (
    <Card className="overflow-hidden">
      <CardHeader
        title="Configuration profiles"
        description="Settings installed on enrolled Macs, iPhones and iPads, kept in step: a new or changed profile installs right away, a removed one comes off. Each is installed only on the kinds of device it's made for."
        actions={
          can("devices:enforce") ? (
            <Button size="sm" onClick={() => setAdding(true)}>
              <Plus className="size-3.5" /> Add profile
            </Button>
          ) : null
        }
      />
      <ErrorBanner error={del.error} />
      {list.data?.data.length ? (
        <ul className="divide-y divide-border">
          {list.data.data.map((p) => (
            <li key={p.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-[13px]">
              <span className="min-w-0">
                <span className="font-medium">{p.name}</span>{" "}
                <span className="text-xs text-fg-muted">
                  {p.platforms.map((x) => PLATFORM_LABEL[x]).join(", ")} · {p.target.all ? "every device" : `people in ${(p.target.group_ids ?? []).map(groupName).join(", ")}`} · {p.payload_types.join(", ")}
                </span>
              </span>
              <span className="flex items-center gap-1.5">
                {p.counts.installed ? <StatusPill tone="success">{p.counts.installed} installed</StatusPill> : null}
                {p.counts.installing ? <StatusPill>{p.counts.installing} installing</StatusPill> : null}
                {p.counts.failed ? <StatusPill tone="danger">{p.counts.failed} failed</StatusPill> : null}
                {can("devices:enforce") ? (
                  <Button size="sm" variant="ghost" aria-label={`Delete ${p.name}`} onClick={() => del.mutate(p.id)}>
                    <Trash2 className="size-3.5" />
                  </Button>
                ) : null}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState icon={<FileCog className="size-5" />} title="No profiles yet" description="Add Wi-Fi, screen lock, firewall or your own .mobileconfig." />
      )}
      {adding ? <AddProfile groups={groups.data?.data ?? []} onClose={() => setAdding(false)} /> : null}
    </Card>
  );
}

function AddProfile({ groups, onClose }: { groups: { id: string; name: string }[]; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [kind, setKind] = useState<Kind>("passcode");
  const [name, setName] = useState("Passcode");
  const [platforms, setPlatforms] = useState<Platform[]>(["macos", "ios", "ipados"]);
  const [groupId, setGroupId] = useState("");
  const [v, setV] = useState<Record<string, string>>({ idle_minutes: "10" });
  const target = groupId ? { group_ids: [groupId] } : { all: true as const };
  const settings = () =>
    kind === "passcode" ? { min_length: Number(v.min_length || 6), auto_lock_minutes: Number(v.auto_lock || 5) } : kind === "screen_lock" ? { idle_minutes: Number(v.idle_minutes || 10) } : kind === "firewall" ? { stealth: v.stealth === "1", block_all_incoming: false } : kind === "wifi" ? { ssid: v.ssid ?? "", password: v.password ?? "" } : kind === "login_message" ? { message: v.message ?? "" } : {};
  const save = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        kind === "upload"
          ? unwrap(api.POST("/v1/apple-mdm/profiles", { body: { name, mobileconfig: v.xml ?? "", target, platforms } }))
          : unwrap(api.POST("/v1/apple-mdm/profiles/template", { body: { name, kind, settings: settings(), target } })),
      ),
    onSuccess: () => (toast.success("Profile saved", { description: "Installing on the targeted devices." }), qc.invalidateQueries({ queryKey: ["apple-mdm-profiles"] }), onClose()),
  });
  const set = (k: string) => (e: { target: { value: string } }) => setV({ ...v, [k]: e.target.value });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Add a configuration profile" className="max-w-lg">
        <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), save.mutate())}>
          <ErrorBanner error={save.error} />
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Kind" htmlFor="pf-kind">
              <Select id="pf-kind" className="w-full" value={kind} onChange={(e) => (setKind(e.target.value as Kind), setName(KINDS.find((k) => k.kind === e.target.value)!.label))}>
                {KINDS.map((k) => (
                  <option key={k.kind} value={k.kind}>
                    {k.label} ({k.where})
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Name" htmlFor="pf-name">
              <Input id="pf-name" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
          </div>
          {kind === "passcode" ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Minimum length" htmlFor="pf-minlen">
                <Input id="pf-minlen" type="number" min={4} max={16} value={v.min_length ?? "6"} onChange={set("min_length")} />
              </Field>
              <Field label="Lock after (minutes idle)" htmlFor="pf-autolock" hint="1 to 5 minutes (iPhone and iPad limits).">
                <Input id="pf-autolock" type="number" min={1} max={5} value={v.auto_lock ?? "5"} onChange={set("auto_lock")} />
              </Field>
            </div>
          ) : kind === "screen_lock" ? (
            <Field label="Lock after (minutes idle)" htmlFor="pf-idle">
              <Input id="pf-idle" type="number" min={1} max={60} value={v.idle_minutes ?? "10"} onChange={set("idle_minutes")} />
            </Field>
          ) : kind === "firewall" ? (
            <label className="flex items-center gap-2 text-[13px]">
              <input type="checkbox" checked={v.stealth === "1"} onChange={(e) => setV({ ...v, stealth: e.target.checked ? "1" : "" })} /> Stealth mode (don't answer probes)
            </label>
          ) : kind === "wifi" ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Network name (SSID)" htmlFor="pf-ssid">
                <Input id="pf-ssid" value={v.ssid ?? ""} onChange={set("ssid")} />
              </Field>
              <Field label="Password (WPA2)" htmlFor="pf-pw">
                <Input id="pf-pw" type="password" autoComplete="off" value={v.password ?? ""} onChange={set("password")} />
              </Field>
            </div>
          ) : kind === "login_message" ? (
            <Field label="Message" htmlFor="pf-msg">
              <Input id="pf-msg" value={v.message ?? ""} onChange={set("message")} placeholder="Property of Acme. Report lost devices to IT." />
            </Field>
          ) : kind === "upload" ? (
            <>
              <Field label="Profile (.mobileconfig, XML)" htmlFor="pf-xml" hint="Unsigned. Profiles that enroll in another MDM are refused.">
                <textarea id="pf-xml" rows={6} spellCheck={false} className="w-full rounded-md border border-border bg-bg-subtle p-2 font-mono text-[11px]" value={v.xml ?? ""} onChange={set("xml")} />
              </Field>
              <div className="flex flex-wrap gap-4 text-[13px]">
                <span className="font-medium">For</span>
                {(["macos", "ios", "ipados"] as const).map((p) => (
                  <label key={p} className="flex items-center gap-1.5">
                    <input type="checkbox" checked={platforms.includes(p)} onChange={(e) => setPlatforms(e.target.checked ? [...platforms, p] : platforms.filter((x) => x !== p))} />
                    {PLATFORM_LABEL[p]}
                  </label>
                ))}
              </div>
            </>
          ) : null}
          <Field label="Install on" htmlFor="pf-target">
            <Select id="pf-target" className="w-full" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
              <option value="">Every enrolled device it's made for</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  Devices of people in {g.name}
                </option>
              ))}
            </Select>
          </Field>
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={save.isPending} disabled={!name.trim() || (kind === "upload" && !platforms.length)}>
              Save and install
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
