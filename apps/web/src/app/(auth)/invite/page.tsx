"use client";

import { useQuery } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { api, bffAuth, fieldErrors, nextStepUrl, unwrap, type SignInResult } from "@/lib/api";

function AcceptInvite() {
  const router = useRouter();
  const token = useSearchParams().get("token") ?? "";
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const invite = useQuery({
    queryKey: ["invite", token],
    queryFn: () => unwrap(api.GET("/v1/invitations/{token}", { params: { path: { token } } })),
    enabled: !!token,
    retry: false,
  });

  if (!token || invite.error) {
    return (
      <div className="space-y-3 text-center">
        <h1 className="text-lg font-semibold">Invitation not valid</h1>
        <ErrorBanner error={invite.error ?? new Error("This link is missing its invitation token.")} />
      </div>
    );
  }
  if (!invite.data) return <p className="text-center text-[13px] text-fg-muted">Loading invitation…</p>;

  const mismatch = confirm.length > 0 && confirm !== password;
  return (
    <form
      className="space-y-4"
      onSubmit={async (e) => {
        e.preventDefault();
        if (mismatch) return;
        setBusy(true);
        setError(null);
        try {
          const r = await bffAuth<SignInResult>("accept-invite", { token, password });
          router.replace(nextStepUrl(r, "/"));
        } catch (err) {
          setError(err);
        } finally {
          setBusy(false);
        }
      }}
    >
      <div>
        <h1 className="text-lg font-semibold">Join {invite.data.organization_name}</h1>
        <p className="mt-1 text-[13px] text-fg-muted">
          Set a password for <span className="font-medium text-fg">{invite.data.email}</span>.
        </p>
      </div>
      {!fieldErrors(error).password ? <ErrorBanner error={error} /> : null}
      <Field label="Password" htmlFor="pw" hint="At least 12 characters. A passphrase works well." error={fieldErrors(error).password}>
        <Input id="pw" type="password" autoComplete="new-password" required minLength={12} autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      <Field label="Confirm password" htmlFor="pw2" error={mismatch ? "Passwords don't match" : undefined}>
        <Input id="pw2" type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      </Field>
      <Button type="submit" variant="primary" size="lg" className="w-full" loading={busy} disabled={mismatch}>
        Join {invite.data.organization_name}
      </Button>
    </form>
  );
}

export default function InvitePage() {
  return (
    <Suspense>
      <AcceptInvite />
    </Suspense>
  );
}
