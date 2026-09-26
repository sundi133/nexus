"use client";

import { KeyRound, MailCheck } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";

function ForgotPassword() {
  const params = useSearchParams();
  const [email, setEmail] = useState(params.get("email") ?? "");
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  if (sent) {
    return (
      <div className="space-y-3 text-center">
        <div className="mx-auto w-fit rounded-full bg-primary-soft p-2.5 text-primary">
          <MailCheck className="size-5" />
        </div>
        <h1 className="text-lg font-semibold">Check your email</h1>
        <p className="text-[13px] text-fg-muted">If {email} has a Nexus account, a link to choose a new password is on its way. It works once and expires in 30 minutes.</p>
        <Link href="/login" className="inline-block text-[13px] font-medium text-primary hover:underline">
          Back to sign in
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
          await unwrap(api.POST("/v1/auth/password-reset", { body: { email: email.trim() } }));
          setSent(true);
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
        <h1 className="text-lg font-semibold">Reset your password</h1>
        <p className="mt-1 text-[13px] text-fg-muted">We'll email you a link. You'll still need your usual MFA method to sign in.</p>
      </div>
      <ErrorBanner error={error} />
      <Field label="Work email" htmlFor="email">
        <Input id="email" type="email" autoComplete="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      <Button type="submit" variant="primary" size="lg" className="w-full" loading={busy} disabled={!email.includes("@")}>
        Send reset link
      </Button>
      <Link href="/login" className="block text-center text-[13px] text-fg-muted hover:text-fg">
        Back to sign in
      </Link>
    </form>
  );
}

export default function ForgotPasswordPage() {
  return (
    <Suspense>
      <ForgotPassword />
    </Suspense>
  );
}
