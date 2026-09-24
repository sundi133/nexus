"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, CircleAlert, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { ActivityList } from "@/components/features/activity";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, PageHeader, Skeleton } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { qk, useCan } from "@/lib/queries";
import { cn, pluralize } from "@/lib/utils";

type Settings = Schemas["OrgSettings"];
const POLICIES: { value: Settings["mfa_policy"]; title: string; description: string }[] = [
  { value: "everyone", title: "Everyone", description: "Recommended. Every account needs a second step." },
  { value: "admins", title: "Admins only", description: "Anyone with an admin role needs MFA." },
  { value: "off", title: "Not required", description: "People can choose. Not recommended." },
];

export default function OrganizationSettingsPage() {
  const qc = useQueryClient();
  const can = useCan();
  const withStepUp = useStepUp();
  const editable = can("org:manage");
  const settings = useQuery({ queryKey: ["org-settings"], queryFn: () => unwrap(api.GET("/v1/org/settings")) });
  const baseline = useQuery({ queryKey: ["baseline"], queryFn: () => unwrap(api.GET("/v1/org/baseline")) });
  const history = useQuery({
    queryKey: ["audit", { type: "org.settings_updated" }],
    queryFn: () => unwrap(api.GET("/v1/audit/events", { params: { query: { type: "org.settings_updated", limit: 10 } } })),
  });
  const [draft, setDraft] = useState<Settings | null>(null);
  const server = useRef<Settings | null>(null);
  // Follow server changes (e.g. the baseline was applied) unless there are unsaved edits.
  useEffect(() => {
    if (!settings.data) return;
    setDraft((d) => (!d || JSON.stringify(d) === JSON.stringify(server.current) ? settings.data! : d));
    server.current = settings.data;
  }, [settings.data]);

  const impact = useQuery({
    queryKey: ["mfa-impact", draft?.mfa_policy],
    queryFn: () => unwrap(api.GET("/v1/org/settings/impact", { params: { query: { mfa_policy: draft!.mfa_policy } } })),
    enabled: !!draft,
  });

  const refresh = () => {
    for (const k of [["org-settings"], ["baseline"], ["audit"], qk.overview]) qc.invalidateQueries({ queryKey: k });
  };
  const save = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.PATCH("/v1/org/settings", { body: draft! }))),
    onSuccess: (s) => {
      setDraft(s);
      refresh();
      toast.success("Security settings saved");
    },
  });
  const apply = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/org/baseline/apply"))),
    onSuccess: (r) => {
      refresh();
      toast.success(r.applied.length ? "Secure baseline applied" : "Already at baseline");
    },
  });

  const dirty = draft && settings.data && JSON.stringify(draft) !== JSON.stringify(settings.data);
  const fixable = baseline.data?.items.filter((i) => !i.compliant && i.auto_apply) ?? [];

  return (
    <>
      <PageHeader title="Organization" description="Security policy for everyone in your organization." />
      <div className="space-y-5">
        <Card id="baseline">
          <CardHeader
            title={
              <span className="flex items-center gap-2">
                <ShieldCheck className="size-4 text-primary" /> Secure baseline
              </span>
            }
            description={
              baseline.data ? `${Math.round(baseline.data.score * 100)}% of recommended settings in place` : "Recommended settings, with impact shown before anything changes"
            }
            actions={
              editable && fixable.length ? (
                <Button variant="primary" onClick={() => apply.mutate()} loading={apply.isPending}>
                  Apply {pluralize(fixable.length, "recommendation")}
                </Button>
              ) : null
            }
          />
          {baseline.isPending ? (
            <Skeleton className="m-4 h-24" />
          ) : (
            <ul className="divide-y divide-border">
              {baseline.data?.items.map((i) => (
                <li key={i.id} className="flex gap-3 px-4 py-3">
                  {i.compliant ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" /> : <CircleAlert className="mt-0.5 size-4 shrink-0 text-warning" />}
                  <div className="min-w-0 flex-1 text-[13px]">
                    <p className="font-medium">{i.title}</p>
                    <p className="text-fg-muted">{i.description}</p>
                    {!i.compliant ? (
                      <p className="mt-1 text-xs text-fg-muted">
                        <span className="font-medium text-fg">Now:</span> {i.current} → <span className="font-medium text-fg">Recommended:</span> {i.recommended}.{" "}
                        {i.impact}
                      </p>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader title="Multi-factor authentication" description="Who must use a second step to sign in." />
          {draft ? (
            <div className="space-y-4 p-4">
              <div className="grid gap-2 md:grid-cols-3" role="radiogroup" aria-label="MFA requirement">
                {POLICIES.map((p) => (
                  <button
                    key={p.value}
                    type="button"
                    role="radio"
                    aria-checked={draft.mfa_policy === p.value}
                    disabled={!editable}
                    onClick={() => setDraft({ ...draft, mfa_policy: p.value })}
                    className={cn(
                      "rounded-lg border p-3 text-left transition-colors disabled:cursor-not-allowed",
                      draft.mfa_policy === p.value ? "border-primary bg-primary-soft" : "border-border hover:bg-bg-subtle",
                    )}
                  >
                    <span className="block text-[13px] font-medium">{p.title}</span>
                    <span className="mt-0.5 block text-xs text-fg-muted">{p.description}</span>
                  </button>
                ))}
              </div>
              {impact.data && draft.mfa_policy !== "off" ? (
                <p className="rounded-md bg-bg-subtle px-3 py-2 text-[13px] text-fg-muted">
                  {impact.data.users_to_enroll
                    ? `${pluralize(impact.data.users_to_enroll, "person")} without MFA will be asked to set it up at their next sign-in. Nobody is signed out.`
                    : "Everyone this applies to already has MFA."}
                </p>
              ) : null}
              <div className="flex items-center gap-3">
                <label htmlFor="ttl" className="text-[13px] font-medium">
                  Sign-ins last
                </label>
                <Select
                  id="ttl"
                  disabled={!editable}
                  value={draft.session_ttl_hours}
                  onChange={(e) => setDraft({ ...draft, session_ttl_hours: Number(e.target.value) })}
                >
                  {[1, 4, 8, 12, 24, 72, 168].map((h) => (
                    <option key={h} value={h}>
                      {h < 24 ? `${h} hour${h > 1 ? "s" : ""}` : `${h / 24} day${h > 24 ? "s" : ""}`}
                    </option>
                  ))}
                </Select>
              </div>
              {editable ? (
                <div className="flex justify-end gap-2 border-t border-border pt-4">
                  <Button onClick={() => setDraft(settings.data!)} disabled={!dirty}>
                    Discard
                  </Button>
                  <Button variant="primary" onClick={() => save.mutate()} disabled={!dirty} loading={save.isPending}>
                    Save changes
                  </Button>
                </div>
              ) : (
                <p className="text-xs text-fg-muted">Only owners and admins can change these settings.</p>
              )}
            </div>
          ) : (
            <Skeleton className="m-4 h-32" />
          )}
        </Card>

        <Card className="overflow-hidden">
          <CardHeader title="Change history" description="Every change to these settings: who, when and what." />
          {history.data?.data.length ? (
            <ul className="divide-y divide-border">
              {history.data.data.map((e) => (
                <li key={e.id} className="px-4 py-2.5 text-[13px]">
                  <ActivityList events={[e]} compact />
                  <div className="-mt-1 pb-1 pl-10 text-xs text-fg-muted">
                    {Object.entries((e.details.changes ?? {}) as Record<string, { from: unknown; to: unknown }>).map(([k, v]) => (
                      <span key={k} className="mr-3">
                        <code className="font-mono">{k}</code>: {String(v.from)} → <span className="font-medium text-fg">{String(v.to)}</span>
                      </span>
                    ))}
                    {e.details.via === "secure_baseline" ? <span className="text-primary">via secure baseline</span> : null}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No changes yet" />
          )}
        </Card>
      </div>
    </>
  );
}
