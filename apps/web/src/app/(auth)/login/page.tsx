"use client";

import { Fingerprint } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { bffAuth, goTo, nextStepUrl, type SignInResult } from "@/lib/api";
import { passkeyErrorMessage, signInWithPasskey, usePasskeysSupported } from "@/lib/passkeys";
import { MfaVerify } from "@/components/features/mfa-verify";

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") || "/";
  const [step, setStep] = useState<"password" | "mfa">(params.get("step") === "mfa" ? "mfa" : "password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<null | "password" | "passkey">(null);
  const [error, setError] = useState<unknown>(null);
  const passkeys = usePasskeysSupported();

  const go = (r: SignInResult) => {
    if (r.session.state === "pending_mfa") setStep("mfa");
    else goTo(nextStepUrl(r, next), router);
  };

  async function submitPassword(e: React.FormEvent) {
    e.preventDefault();
    setBusy("password");
    setError(null);
    try {
      go(await bffAuth<SignInResult>("login", { email, password }));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(null);
    }
  }

  async function passkey() {
    if (!email) {
      setError(new Error("Enter your work email first, then use your passkey."));
      return;
    }
    setBusy("passkey");
    setError(null);
    try {
      go(await signInWithPasskey(email));
    } catch (err) {
      setError(new Error(passkeyErrorMessage(err)));
    } finally {
      setBusy(null);
    }
  }

  if (step === "mfa") return <MfaVerify next={next} onRestart={() => setStep("password")} />;

  return (
    <form onSubmit={submitPassword} className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Sign in</h1>
        <p className="mt-1 text-[13px] text-fg-muted">Welcome back. Sign in to your organization.</p>
      </div>
      <ErrorBanner error={error} />
      <Field label="Work email" htmlFor="email">
        <Input id="email" type="email" autoComplete="username webauthn" autoFocus required value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      {passkeys ? (
        <>
          <Button type="button" variant="primary" size="lg" className="w-full" loading={busy === "passkey"} onClick={passkey}>
            <Fingerprint /> Sign in with a passkey
          </Button>
          <div className="flex items-center gap-3 text-xs text-fg-subtle">
            <span className="h-px flex-1 bg-border" /> or use your password <span className="h-px flex-1 bg-border" />
          </div>
        </>
      ) : null}
      <Field label="Password" htmlFor="password">
        <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <Link href={`/forgot-password${email ? `?email=${encodeURIComponent(email)}` : ""}`} className="mt-1 block text-right text-xs text-fg-muted hover:text-fg">
          Forgot password?
        </Link>
      </Field>
      <Button type="submit" variant={passkeys ? "secondary" : "primary"} size="lg" className="w-full" loading={busy === "password"} disabled={!password}>
        Continue with password
      </Button>
      <p className="text-center text-[13px] text-fg-muted">
        New to Nexus?{" "}
        <Link href="/signup" className="font-medium text-primary hover:underline">
          Create an organization
        </Link>
      </p>
    </form>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
