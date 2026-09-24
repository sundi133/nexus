"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, KeyRound, RefreshCw } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime } from "@/lib/utils";
import { ConfirmAction } from "./confirm-action";

const daysUntil = (iso: string) => Math.floor((new Date(iso).getTime() - Date.now()) / 86_400_000);

/** SSO signing material and its rotation (SPEC SSO-07). */
export function SigningKeysCard() {
  const qc = useQueryClient();
  const can = useCan();
  const withStepUp = useStepUp();
  const [confirm, setConfirm] = useState<null | "oidc" | "saml-next" | "saml-activate" | "saml-discard">(null);
  const keys = useQuery({ queryKey: ["signing-keys"], queryFn: () => unwrap(api.GET("/v1/org/signing-keys")) });
  const done = (msg: string) => () => {
    qc.invalidateQueries({ queryKey: ["signing-keys"] });
    qc.invalidateQueries({ queryKey: ["apps"] });
    qc.invalidateQueries({ queryKey: ["app"] });
    qc.invalidateQueries({ queryKey: ["overview"] });
    toast.success(msg);
  };
  const act = useMutation({
    mutationFn: (what: NonNullable<typeof confirm>) =>
      withStepUp(() =>
        unwrap(
          what === "oidc"
            ? api.POST("/v1/org/signing-keys/oidc/rotate")
            : what === "saml-next"
              ? api.POST("/v1/org/signing-keys/saml/next")
              : what === "saml-activate"
                ? api.POST("/v1/org/signing-keys/saml/activate")
                : api.DELETE("/v1/org/signing-keys/saml/next"),
        ),
      ),
  });

  const saml = keys.data?.data.filter((k) => k.purpose === "saml") ?? [];
  const active = saml.find((k) => k.status === "active");
  const next = saml.find((k) => k.status === "next");
  const oidc = keys.data?.data.find((k) => k.purpose === "oidc" && k.status === "active");
  const editable = can("apps:write");
  const download = (pem: string, name: string) => (
    <Button asChild size="sm" variant="ghost">
      <a href={`data:application/x-pem-file;charset=utf-8,${encodeURIComponent(pem)}`} download={name}>
        <Download /> .pem
      </a>
    </Button>
  );

  return (
    <Card id="certificates">
      <CardHeader title="SSO certificates and keys" description="What apps use to trust sign-ins from Nexus. Rotate them regularly, and always before they expire." />
      {keys.isPending ? (
        <Skeleton className="m-4 h-24" />
      ) : (
        <div className="divide-y divide-border">
          <div className="flex flex-wrap items-center gap-3 px-4 py-3 text-[13px]">
            <KeyRound className="size-4 text-fg-muted" />
            <div className="min-w-0 flex-1">
              <p className="font-medium">SAML signing certificate</p>
              {active ? (
                <p className="text-xs text-fg-muted">
                  <code className="font-mono">{active.fingerprint?.slice(0, 23)}…</code> · expires {new Date(active.expires_at!).toLocaleDateString()} ({daysUntil(active.expires_at!)} days)
                </p>
              ) : null}
            </div>
            {active ? <StatusPill tone={daysUntil(active.expires_at!) < 60 ? "warning" : "success"}>Active</StatusPill> : null}
            {active?.certificate ? download(active.certificate, "nexus-saml-current.pem") : null}
            {editable && !next ? (
              <Button size="sm" onClick={() => setConfirm("saml-next")}>
                <RefreshCw /> Start rotation
              </Button>
            ) : null}
          </div>
          {next ? (
            <div className="flex flex-wrap items-center gap-3 bg-primary-soft/40 px-4 py-3 text-[13px]">
              <RefreshCw className="size-4 text-primary" />
              <div className="min-w-0 flex-1">
                <p className="font-medium">Next certificate (published, not signing yet)</p>
                <p className="text-xs text-fg-muted">
                  <code className="font-mono">{next.fingerprint?.slice(0, 23)}…</code> · created {formatDateTime(next.created_at)}. Add it to apps that pin certificates, then activate.
                </p>
              </div>
              {next.certificate ? download(next.certificate, "nexus-saml-next.pem") : null}
              {editable ? (
                <>
                  <Button size="sm" variant="ghost" onClick={() => setConfirm("saml-discard")}>
                    Discard
                  </Button>
                  <Button size="sm" variant="primary" onClick={() => setConfirm("saml-activate")}>
                    Activate
                  </Button>
                </>
              ) : null}
            </div>
          ) : null}
          <div className="flex flex-wrap items-center gap-3 px-4 py-3 text-[13px]">
            <KeyRound className="size-4 text-fg-muted" />
            <div className="min-w-0 flex-1">
              <p className="font-medium">OIDC token signing key</p>
              <p className="text-xs text-fg-muted">{oidc ? `RS256 · kid ${oidc.kid} · since ${formatDateTime(oidc.created_at)}. Apps pick up new keys from JWKS automatically.` : "Created on first OIDC sign-in."}</p>
            </div>
            {editable && oidc ? (
              <Button size="sm" onClick={() => setConfirm("oidc")}>
                <RefreshCw /> Rotate
              </Button>
            ) : null}
          </div>
        </div>
      )}

      <ConfirmAction
        open={confirm === "saml-next"}
        onOpenChange={(v) => !v && setConfirm(null)}
        title="Start a SAML certificate rotation?"
        effects={[
          "Create a new certificate and publish it in IdP metadata next to the current one",
          "Nothing changes for sign-ins yet: the current certificate keeps signing",
          "Next: add the new certificate to apps that pin it, then activate",
        ]}
        confirmLabel="Create next certificate"
        askReason={false}
        onConfirm={() => act.mutateAsync("saml-next").then(done("Next certificate created"))}
      />
      <ConfirmAction
        open={confirm === "saml-activate"}
        onOpenChange={(v) => !v && setConfirm(null)}
        title="Activate the new SAML certificate?"
        effects={[
          "Sign-ins are signed with the new certificate from now on",
          "Apps that still only trust the old certificate will reject sign-ins until updated",
          "The old certificate is retired and removed from metadata",
        ]}
        confirmLabel="Activate"
        danger
        askReason={false}
        onConfirm={() => act.mutateAsync("saml-activate").then(done("New certificate is active"))}
      />
      <ConfirmAction
        open={confirm === "saml-discard"}
        onOpenChange={(v) => !v && setConfirm(null)}
        title="Discard the next certificate?"
        effects={["Remove it from metadata; the current certificate stays active"]}
        confirmLabel="Discard"
        askReason={false}
        onConfirm={() => act.mutateAsync("saml-discard").then(done("Rotation discarded"))}
      />
      <ConfirmAction
        open={confirm === "oidc"}
        onOpenChange={(v) => !v && setConfirm(null)}
        title="Rotate the OIDC signing key?"
        effects={["New tokens are signed with a new key published in JWKS", "The old key stays in JWKS for 7 days so existing tokens keep verifying"]}
        confirmLabel="Rotate key"
        askReason={false}
        onConfirm={() => act.mutateAsync("oidc").then(done("OIDC key rotated"))}
      />
    </Card>
  );
}
