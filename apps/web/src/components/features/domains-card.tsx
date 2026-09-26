"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Plus, RefreshCw, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, ErrorBanner, StatusPill } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { timeAgo } from "@/lib/utils";

const KEY = ["org-domains"];

/** ORG-02: prove you own your email domains, so nobody else can claim your people. */
export function DomainsCard({ editable }: { editable: boolean }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const domains = useQuery({ queryKey: KEY, queryFn: () => unwrap(api.GET("/v1/org/domains")) });
  const [domain, setDomain] = useState("");
  const add = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/org/domains", { body: { domain: domain.trim() } })),
    onSuccess: (r) => (qc.setQueryData(KEY, r), setDomain("")),
  });
  const verify = useMutation({
    mutationFn: (id: string) => unwrap(api.POST("/v1/org/domains/{id}/verify", { params: { path: { id } } })),
    onSuccess: (r, id) => {
      qc.setQueryData(KEY, r);
      const d = r.data.find((x) => x.id === id);
      if (d?.status === "verified") toast.success(`${d.domain} is verified`, { description: "Only your organization can add people from it now." });
      else toast.error(d?.last_error || "Not found yet");
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => withStepUp(() => unwrap(api.DELETE("/v1/org/domains/{id}", { params: { path: { id } } }))),
    onSuccess: (r) => qc.setQueryData(KEY, r),
  });
  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <Globe className="size-4 text-fg-muted" /> Domains
          </span>
        }
        description="Verify the email domains you own. Once verified, no other Nexus organization can sign up with, invite or sync people from them."
      />
      <div className="space-y-3 p-4">
        {domains.data?.data.map((d) => (
          <div key={d.id} className="rounded-md border border-border p-3 text-[13px]">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{d.domain}</span>
              {d.status === "verified" ? <StatusPill tone="success">Verified</StatusPill> : d.status === "failing" ? <StatusPill tone="warning">Record missing</StatusPill> : <StatusPill>Not verified yet</StatusPill>}
              <span className="text-xs text-fg-muted">{d.people === 1 ? "1 person" : `${d.people.toLocaleString()} people`}</span>
              <span className="flex-1" />
              {editable ? (
                <>
                  {d.status !== "verified" ? (
                    <Button size="sm" variant="secondary" loading={verify.isPending && verify.variables === d.id} onClick={() => verify.mutate(d.id)}>
                      <RefreshCw /> Check now
                    </Button>
                  ) : null}
                  <Button size="sm" variant="ghost" aria-label={`Remove ${d.domain}`} onClick={() => remove.mutate(d.id)}>
                    <Trash2 />
                  </Button>
                </>
              ) : null}
            </div>
            {d.status !== "verified" ? (
              <div className="mt-2 space-y-2 text-xs text-fg-muted">
                <p>Add this TXT record at your DNS provider, then check. It can take up to an hour to appear.</p>
                <CopyField label="Name" value={d.record.name} />
                <CopyField label="Value" value={d.record.value} />
                {d.last_error ? <p className="text-warning">{d.last_error}{d.last_checked_at ? ` (checked ${timeAgo(d.last_checked_at)})` : ""}</p> : null}
              </div>
            ) : null}
          </div>
        ))}
        {editable ? (
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              add.mutate();
            }}
          >
            <Input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="yourcompany.com" aria-label="Domain" className="max-w-xs" />
            <Button type="submit" variant="secondary" disabled={!domain.includes(".")} loading={add.isPending}>
              <Plus /> Add domain
            </Button>
          </form>
        ) : null}
        <ErrorBanner error={add.error ?? remove.error ?? verify.error} />
      </div>
    </Card>
  );
}
