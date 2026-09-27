"use client";

import { CheckCircle2, KeyRound } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { api, fieldErrors, unwrap } from "@/lib/api";

function ResetPassword() {
  const params = useSearchParams();
  const token = params.get("token") ?? "";
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const errs = fieldErrors(error);

  if (done) {
    return (
      <div className="space-y-3 text-center">
        <div className="mx-auto w-fit rounded-full bg-success-soft p-2.5 text-success">
          <CheckCircle2 className="size-5" />
        </div>
        <h1 className="text-lg font-semibold">Password changed</h1>
        <p className="text-[13px] text-fg-muted">You've been signed out everywhere. Sign in with your new password and your usual MFA method.</p>
        <Link href="/login" className="inline-block text-[13px] font-medium text-primary hover:underline">
          Sign in
        </Link>
      </div>
    );
  }
  return (
    <form
      className="space-y-4"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
          await unwrap(api.POST("/v1/auth/password-reset/complete", { body: { token, password } }));
          setDone(true);
        } catch (err) {
          setError(err);
        } finally {
          setBusy(false);
        }
      }}
    >
      <div className="flex flex-col items-center text-center">
        <div className="mb-3 rounded-full bg-primary-soft p-2.5 text-primary">
          <KeyRound className="size-5" />
        </div>
        <h1 className="text-lg font-semibold">Choose a new password</h1>
        <p className="mt-1 text-[13px] text-fg-muted">At least 12 characters. A few unrelated words work well.</p>
      </div>
      <ErrorBanner error={error} />
      <Field label="New password" htmlFor="pw" error={errs.password}>
        <Input id="pw" type="password" autoComplete="new-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      <Field label="Confirm" htmlFor="pw2" error={confirm && confirm !== password ? "Doesn't match" : undefined}>
        <Input id="pw2" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      </Field>
      <Button type="submit" variant="primary" size="lg" className="w-full" loading={busy} disabled={!token || password.length < 12 || password !== confirm}>
        Set new password
      </Button>
    </form>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPassword />
    </Suspense>
  );
}
