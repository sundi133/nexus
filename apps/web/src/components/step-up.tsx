"use client";

import { useQuery } from "@tanstack/react-query";
import { Fingerprint, ShieldCheck } from "lucide-react";
import { createContext, useCallback, useContext, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, ApiProblem, unwrap } from "@/lib/api";
import { passkeyErrorMessage, usePasskeysSupported, verifyWithPasskey } from "@/lib/passkeys";

type Run = <T>(fn: () => Promise<T>) => Promise<T>;
const Ctx = createContext<Run>((fn) => fn());

/**
 * `const withStepUp = useStepUp(); await withStepUp(() => doSensitiveThing())`
 * If the API answers `step_up_required`, we ask for MFA inline and retry once,
 * so admins never lose their place (docs/UI.md §4.3).
 */
export const useStepUp = () => useContext(Ctx);

export function StepUpProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const pending = useRef<{ resolve: () => void; reject: (e: unknown) => void } | null>(null);

  const run: Run = useCallback(async (fn) => {
    try {
      return await fn();
    } catch (err) {
      if (!(err instanceof ApiProblem && err.code === "step_up_required")) throw err;
      await new Promise<void>((resolve, reject) => {
        pending.current = { resolve, reject };
        setOpen(true);
      });
      return fn();
    }
  }, []);

  const finish = (ok: boolean) => {
    setOpen(false);
    if (ok) pending.current?.resolve();
    else pending.current?.reject(new Error("Verification cancelled"));
    pending.current = null;
  };

  return (
    <Ctx.Provider value={run}>
      {children}
      <StepUpDialog open={open} onDone={finish} />
    </Ctx.Provider>
  );
}

function StepUpDialog({ open, onDone }: { open: boolean; onDone: (ok: boolean) => void }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const factors = useQuery({ queryKey: ["factors"], queryFn: () => unwrap(api.GET("/v1/me/factors")), enabled: open });
  const types = new Set(factors.data?.data.filter((f) => f.verified).map((f) => f.type));
  const passkeys = usePasskeysSupported();

  const attempt = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      setCode("");
      onDone(true);
    } catch (err) {
      setError(new Error(passkeyErrorMessage(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onDone(false)}>
      <DialogContent title="Confirm it's you" description="This is a sensitive action. Verify with MFA to continue. You won't be asked again for 10 minutes.">
        <div className="space-y-3">
          <ErrorBanner error={error} />
          {types.has("webauthn") && passkeys ? (
            <Button variant="primary" size="lg" className="w-full" loading={busy} onClick={() => attempt(verifyWithPasskey)}>
              <Fingerprint /> Use your passkey
            </Button>
          ) : null}
          {types.has("totp") ? (
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                attempt(() => unwrap(api.POST("/v1/auth/mfa/totp", { body: { code } })));
              }}
            >
              <Input
                autoFocus={!types.has("webauthn")}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                placeholder="6-digit code"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                className="h-10 font-mono tracking-widest"
                aria-label="Authenticator code"
              />
              <Button type="submit" size="lg" disabled={code.length !== 6} loading={busy}>
                <ShieldCheck /> Verify
              </Button>
            </form>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}
