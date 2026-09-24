"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Info } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import { Card, PageHeader, Skeleton } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { pluralize } from "@/lib/utils";

type Policy = Schemas["DevicePolicy"];

export default function DevicePoliciesPage() {
  const policies = useQuery({ queryKey: ["device-policies"], queryFn: () => unwrap(api.GET("/v1/device-policies")) });
  const can = useCan();
  return (
    <>
      <PageHeader title="Device policies" description="What a device must meet to count as compliant. Applies to every enrolled device." />
      <div className="mb-4 flex items-start gap-2 rounded-lg border border-primary/20 bg-primary-soft px-4 py-3 text-[13px]">
        <Info className="mt-0.5 size-4 shrink-0 text-primary" />
        <p>
          <span className="font-medium">Audit mode.</span> Non-compliant devices are flagged and their owners are told exactly what to fix. To block sign-in from them, add a conditional access policy that requires a compliant device.
        </p>
      </div>
      {policies.isPending ? (
        <Skeleton className="h-64" />
      ) : (
        <div className="space-y-3">
          {policies.data?.data.map((p) => (
            <PolicyCard key={`${p.key}-${JSON.stringify(p)}`} policy={p} editable={can("devices:write")} />
          ))}
        </div>
      )}
    </>
  );
}

function PolicyCard({ policy, editable }: { policy: Policy; editable: boolean }) {
  const qc = useQueryClient();
  const [enabled, setEnabled] = useState(policy.enabled);
  const [params, setParams] = useState(policy.params as Record<string, unknown>);
  useEffect(() => {
    setEnabled(policy.enabled);
    setParams(policy.params as Record<string, unknown>);
  }, [policy]);
  const dirty = enabled !== policy.enabled || JSON.stringify(params) !== JSON.stringify(policy.params);
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/v1/device-policies/{key}", { params: { path: { key: policy.key } }, body: { enabled, params } })),
    onSuccess: (r) => {
      qc.setQueryData(["device-policies"], { data: r.data });
      qc.invalidateQueries({ queryKey: ["devices"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
      toast.success(`${policy.title} saved`, {
        description: `Re-evaluated ${pluralize(r.reevaluated.devices, "device")}${r.reevaluated.changed ? `; ${r.reevaluated.changed} changed compliance` : ""}.`,
      });
    },
  });
  const minimum = (params.minimum ?? {}) as Record<string, string>;

  return (
    <Card className="p-4">
      <div className="flex items-start gap-3">
        <label className="mt-0.5 inline-flex cursor-pointer items-center">
          <input type="checkbox" className="peer sr-only" checked={enabled} disabled={!editable} onChange={(e) => setEnabled(e.target.checked)} aria-label={`Require ${policy.title}`} />
          <span className="relative h-5 w-9 rounded-full bg-border-strong transition-colors after:absolute after:left-0.5 after:top-0.5 after:size-4 after:rounded-full after:bg-white after:transition-transform peer-checked:bg-primary peer-checked:after:translate-x-4 peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-ring" />
        </label>
        <div className="min-w-0 flex-1">
          <p className="text-[13px] font-semibold">{policy.title}</p>
          <p className="text-[13px] text-fg-muted">{policy.why}</p>
          {enabled && policy.key === "screen_lock" ? (
            <div className="mt-3 flex items-center gap-2 text-[13px]">
              Lock within
              <Select value={String(params.max_delay_minutes ?? 10)} disabled={!editable} onChange={(e) => setParams({ ...params, max_delay_minutes: Number(e.target.value) })} aria-label="Maximum screen lock delay">
                {[0, 1, 2, 5, 10, 15, 30].map((m) => (
                  <option key={m} value={m}>
                    {m === 0 ? "immediately" : `${m} min`}
                  </option>
                ))}
              </Select>
            </div>
          ) : null}
          {enabled && policy.key === "os_version" ? (
            <div className="mt-3 grid gap-2 sm:grid-cols-3">
              {(["macos", "windows", "linux"] as const).map((pl) => (
                <label key={pl} className="text-xs text-fg-muted">
                  Minimum {pl === "macos" ? "macOS" : pl === "windows" ? "Windows" : "Linux"}
                  <Input
                    className="mt-1 font-mono text-xs"
                    placeholder="not enforced"
                    disabled={!editable}
                    value={minimum[pl] ?? ""}
                    onChange={(e) => setParams({ ...params, minimum: { macos: "", windows: "", linux: "", ...minimum, [pl]: e.target.value.trim() } })}
                  />
                </label>
              ))}
            </div>
          ) : null}
        </div>
        {editable && dirty ? (
          <Button size="sm" variant="primary" loading={save.isPending} onClick={() => save.mutate()}>
            Save
          </Button>
        ) : null}
      </div>
    </Card>
  );
}
