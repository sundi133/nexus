"use client";

import { ChangePasswordCard, RecoveryCodesCard } from "@/components/features/account-recovery";
import { NotificationPrefsCard } from "@/components/features/notification-channels";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, KeyRound, Plus, Smartphone, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { MfaEnroll } from "@/components/features/mfa-enroll";
import { SessionsTable } from "@/components/features/sessions-table";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, EmptyState, PageHeader, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { qk } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

const LABEL = { webauthn: "Passkey", totp: "Authenticator app", push: "Nexus Mobile" } as const;

export default function SecurityPage() {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const factors = useQuery({ queryKey: qk.factors, queryFn: () => unwrap(api.GET("/v1/me/factors")) });
  const sessions = useQuery({ queryKey: qk.sessions, queryFn: () => unwrap(api.GET("/v1/me/sessions")) });
  const [adding, setAdding] = useState(false);

  const refresh = () => {
    qc.invalidateQueries({ queryKey: qk.factors });
    qc.invalidateQueries({ queryKey: qk.sessions });
    qc.invalidateQueries({ queryKey: qk.me });
    qc.invalidateQueries({ queryKey: qk.overview });
  };
  const removeFactor = useMutation({
    mutationFn: (id: string) => withStepUp(() => unwrap(api.DELETE("/v1/me/factors/{id}", { params: { path: { id } } }))),
    onSuccess: () => {
      refresh();
      toast.success("MFA method removed");
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/v1/me/sessions/{id}", { params: { path: { id } } })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.sessions });
      toast.success("Session signed out");
    },
  });

  const verified = factors.data?.data.filter((f) => f.verified) ?? [];
  const onlyOne = verified.length === 1;

  return (
    <>
      <PageHeader title="My security" description="Protect your account and see where you're signed in." />
      <div className="space-y-5">
        <Card>
          <CardHeader
            title="Sign-in methods"
            description={verified.length ? "You'll verify with one of these when you sign in." : "Add a second step so a stolen password isn't enough."}
            actions={
              <Button variant="primary" onClick={() => setAdding(true)}>
                <Plus /> Add method
              </Button>
            }
          />
          {verified.length ? (
            <ul className="divide-y divide-border">
              {verified.map((f) => (
                <li key={f.id} className="flex items-center gap-3 px-4 py-3 text-[13px]">
                  {f.type === "webauthn" ? <Fingerprint className="size-4 text-fg-muted" /> : f.type === "push" ? <Smartphone className="size-4 text-primary" /> : <KeyRound className="size-4 text-fg-muted" />}
                  <div className="flex-1">
                    <p className="font-medium">{f.name}</p>
                    <p className="text-xs text-fg-muted">
                      {LABEL[f.type]} · last used {timeAgo(f.last_used_at)}
                    </p>
                  </div>
                  {f.type === "webauthn" ? <StatusPill tone="primary">Phishing-resistant</StatusPill> : <StatusPill tone="success">Active</StatusPill>}
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => removeFactor.mutate(f.id)}
                    aria-label={`Remove ${f.name}`}
                    title={onlyOne ? "Add another method before removing your last one" : undefined}
                    disabled={onlyOne}
                  >
                    <Trash2 />
                  </Button>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No sign-in methods yet" description="Passkeys are the most secure option; Nexus Mobile lets you approve sign-ins with a tap." />
          )}
        </Card>

        <RecoveryCodesCard hasFactor={verified.length > 0} />
        <ChangePasswordCard />
        <NotificationPrefsCard />
        <Card className="overflow-hidden">
          <CardHeader title="Where you're signed in" description="Web, mobile and CLI sessions." />
          {sessions.data?.data.length ? <SessionsTable sessions={sessions.data.data} onRevoke={(id) => revoke.mutate(id)} /> : null}
        </Card>
      </div>
      <Dialog open={adding} onOpenChange={setAdding}>
        <DialogContent title="Add a sign-in method">
          {adding ? (
            <MfaEnroll
              onDone={() => {
                refresh();
                toast.success("Sign-in method added");
                setAdding(false);
              }}
            />
          ) : null}
        </DialogContent>
      </Dialog>
    </>
  );
}
