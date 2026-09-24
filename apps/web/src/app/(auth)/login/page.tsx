"use client";

import { useQuery } from "@tanstack/react-query";
import { Fingerprint, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { api, ApiProblem, bffAuth, nextStepUrl, unwrap, type SignInResult } from "@/lib/api";
import { passkeyErrorMessage, signInWithPasskey, usePasskeysSupported, verifyWithPasskey } from "@/lib/passkeys";
import { PushApproval } from "@/components/features/push-approval";

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
    else router.replace(nextStepUrl(r, next));
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

  if (step === "mfa") return <MfaStep next={next} onRestart={() => setStep("password")} />;

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

function MfaStep({ next, onRestart }: { next: string; onRestart: () => void }) {
  const router = useRouter();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const passkeys = usePasskeysSupported();
  const session = useQuery({ queryKey: ["auth-session"], queryFn: () => unwrap(api.GET("/v1/auth/session")), retry: false });
  const factors = new Set(session.data?.factors ?? []);
  const done = () => router.replace(next.startsWith("/") && !next.startsWith("//") ? next : "/");

  const attempt = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      done();
    } catch (err) {
      if (err instanceof ApiProblem && err.code === "unauthenticated") onRestart();
      setError(new Error(passkeyErrorMessage(err)));
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col items-center text-center">
        <div className="mb-3 rounded-full bg-primary-soft p-2.5 text-primary">
          <ShieldCheck className="size-5" />
        </div>
        <h1 className="text-lg font-semibold">Verify it&apos;s you</h1>
        {session.data ? <p className="mt-1 text-xs text-fg-subtle">{session.data.email}</p> : null}
      </div>
      <ErrorBanner error={error} />
      {factors.has("push") ? <PushApproval onApproved={done} autoStart={!factors.has("webauthn")} /> : null}
      {factors.has("webauthn") && passkeys ? (
        <Button variant={factors.has("push") ? "secondary" : "primary"} size="lg" className="w-full" loading={busy} onClick={() => attempt(verifyWithPasskey)}>
          <Fingerprint /> Use your passkey
        </Button>
      ) : null}
      {factors.has("totp") ? (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            attempt(() => unwrap(api.POST("/v1/auth/mfa/totp", { body: { code } })));
          }}
        >
          <p className="text-center text-[13px] text-fg-muted">Enter the 6-digit code from your authenticator app.</p>
          <Input
            autoFocus={!factors.has("webauthn") && !factors.has("push")}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            className="h-11 text-center font-mono text-lg tracking-[0.5em]"
            aria-label="Verification code"
          />
          <Button type="submit" variant={factors.has("webauthn") || factors.has("push") ? "secondary" : "primary"} size="lg" className="w-full" loading={busy} disabled={code.length !== 6}>
            Verify code
          </Button>
        </form>
      ) : null}
      <button type="button" onClick={onRestart} className="block w-full text-center text-[13px] text-fg-muted hover:text-fg">
        Use a different account
      </button>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
