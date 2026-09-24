"use client";

import { useEffect, useRef, useState } from "react";
import { Smartphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorBanner } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";

type Phase = { kind: "idle" } | { kind: "waiting"; id: string; number: number; expiresAt: number } | { kind: "denied"; reason: string | null } | { kind: "expired" };

/**
 * Sends a push to the user's phone and shows the number to tap. Completes when
 * the phone approves (poll + the session's SSE stream, whichever is first).
 */
export function PushApproval({ onApproved, autoStart }: { onApproved: () => void; autoStart?: boolean }) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const started = useRef(false);

  const send = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await unwrap(api.POST("/v1/auth/mfa/push"));
      setPhase({ kind: "waiting", id: r.challenge_id, number: r.number, expiresAt: new Date(r.expires_at).getTime() });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (autoStart && !started.current) {
      started.current = true;
      void send();
    }
  }, [autoStart]);

  useEffect(() => {
    if (phase.kind !== "waiting") return;
    let stopped = false;
    const check = async () => {
      if (stopped) return;
      if (Date.now() > phase.expiresAt) return setPhase({ kind: "expired" });
      const s = await unwrap(api.GET("/v1/auth/mfa/push/{id}", { params: { path: { id: phase.id } } })).catch(() => null);
      if (!s || stopped) return;
      if (s.status === "approved") onApproved();
      else if (s.status === "denied") setPhase({ kind: "denied", reason: s.reason });
      else if (s.status === "expired") setPhase({ kind: "expired" });
    };
    // Live signal from the stream, with polling as a fallback.
    const es = new EventSource("/bff/v1/me/stream");
    es.addEventListener("challenge", () => void check());
    const timer = setInterval(check, 2000);
    return () => {
      stopped = true;
      es.close();
      clearInterval(timer);
    };
  }, [phase, onApproved]);

  if (phase.kind === "waiting") {
    return (
      <div className="rounded-lg border border-border bg-bg-subtle p-4 text-center" aria-live="polite">
        <p className="text-[13px] text-fg-muted">Open Nexus Mobile and tap</p>
        <p className="my-2 font-mono text-5xl font-semibold tracking-wider text-primary tabular">{phase.number}</p>
        <p className="flex items-center justify-center gap-1.5 text-xs text-fg-subtle">
          <span className="size-2 animate-pulse rounded-full bg-primary" /> Waiting for your phone…
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <ErrorBanner error={error} />
      {phase.kind === "denied" ? (
        <ErrorBanner
          error={new Error(phase.reason === "mistake" ? "The request was declined on your phone." : "This sign-in was blocked from your phone. Your security team has been notified.")}
        />
      ) : null}
      {phase.kind === "expired" ? <ErrorBanner error={new Error("The request expired. Send another one.")} /> : null}
      {phase.kind !== "denied" || phase.reason === "mistake" ? (
        <Button variant="primary" size="lg" className="w-full" onClick={send} loading={busy}>
          <Smartphone /> {phase.kind === "idle" ? "Send a push to my phone" : "Send another push"}
        </Button>
      ) : null}
    </div>
  );
}
