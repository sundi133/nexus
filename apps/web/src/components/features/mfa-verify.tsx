"use client";

import { useQuery } from "@tanstack/react-query";
import { Fingerprint, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { api, ApiProblem, goTo, unwrap } from "@/lib/api";
import { passkeyErrorMessage, usePasskeysSupported, verifyWithPasskey } from "@/lib/passkeys";
import { PushApproval } from "@/components/features/push-approval";

/**
 * Second step of sign-in, also used to step up an active session (e.g. an app
 * whose access policy requires MFA). Offers every factor the user has.
 */
export function MfaVerify({ next, onRestart, subtitle }: { next: string; onRestart: () => void; subtitle?: string }) {
  const router = useRouter();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const passkeys = usePasskeysSupported();
  const session = useQuery({ queryKey: ["auth-session"], queryFn: () => unwrap(api.GET("/v1/auth/session")), retry: false });
  const factors = new Set(session.data?.factors ?? []);
  const done = () => goTo(next.startsWith("/") && !next.startsWith("//") ? next : "/", router);

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
        {subtitle ? <p className="mt-1 text-[13px] text-fg-muted">{subtitle}</p> : null}
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
