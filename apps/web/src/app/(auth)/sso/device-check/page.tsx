"use client";

import { Laptop, Loader2, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { api, ApiProblem, goTo, unwrap } from "@/lib/api";

type State = { step: "checking" } | { step: "no_agent" } | { step: "failed"; message: string };

/**
 * An app's access policy needs to know which device this browser is on.
 * The Nexus agent on this computer signs a one-time challenge (it only
 * answers this console's origin), the API verifies it and binds the session
 * to the device, and we go back to finish signing in to the app.
 */
function DeviceCheck() {
  const router = useRouter();
  const params = useSearchParams();
  const raw = params.get("next") ?? "/";
  const next = raw.startsWith("/") && !raw.startsWith("//") ? raw : "/";
  const app = params.get("app") ?? "this app";
  const [state, setState] = useState<State>({ step: "checking" });
  const started = useRef(false);

  const run = useCallback(async () => {
    setState({ step: "checking" });
    try {
      const ch = await unwrap(api.POST("/v1/me/device-trust/challenge", {}));
      let attestation: string;
      try {
        const res = await fetch(`${ch.agent_url}/v1/attest`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ nonce: ch.nonce }),
          signal: AbortSignal.timeout(4000),
        });
        if (!res.ok) throw new Error(`agent answered ${res.status}`);
        attestation = ((await res.json()) as { attestation: string }).attestation;
      } catch {
        // Not installed, not running, or enrolled to a different console: the browser can't tell which.
        setState({ step: "no_agent" });
        return;
      }
      await unwrap(api.POST("/v1/me/device-trust", { body: { challenge_id: ch.challenge_id, attestation } }));
      goTo(next, router);
    } catch (err) {
      setState({ step: "failed", message: err instanceof ApiProblem ? err.message : "Something went wrong checking this device." });
    }
  }, [next, router]);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void run();
  }, [run]);

  if (state.step === "checking") {
    return (
      <div className="space-y-3 py-4 text-center">
        <Loader2 className="mx-auto size-6 animate-spin text-primary" />
        <h1 className="text-lg font-semibold">Checking this device</h1>
        <p className="text-[13px] text-fg-muted">{app} only allows sign-in from devices managed by your organization.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4 text-center">
      <div className="mx-auto w-fit rounded-full bg-warning-soft p-2.5 text-warning">{state.step === "no_agent" ? <Laptop className="size-5" /> : <ShieldAlert className="size-5" />}</div>
      <h1 className="text-lg font-semibold">{state.step === "no_agent" ? "We couldn't find the Nexus agent" : "This device couldn't be verified"}</h1>
      {state.step === "no_agent" ? (
        <div className="space-y-2 text-left text-[13px] text-fg-muted">
          <p>{app} requires a device managed by your organization. To continue, this computer needs the Nexus agent running:</p>
          <ul className="list-disc space-y-1 pl-5">
            <li>If it isn&apos;t enrolled yet, enroll it from My devices.</li>
            <li>If it is, make sure <code className="rounded bg-bg-subtle px-1 font-mono text-xs">nexus-agent run</code> is running.</li>
            <li>Using a phone or someone else&apos;s computer? Switch to your work device.</li>
          </ul>
        </div>
      ) : (
        <p className="text-[13px] text-fg-muted">{state.message}</p>
      )}
      <div className="flex flex-col gap-2">
        <Button size="lg" className="w-full" onClick={() => void run()}>
          Try again
        </Button>
        <Link href="/my-devices" className="text-[13px] font-medium text-primary hover:underline">
          Go to My devices
        </Link>
      </div>
    </div>
  );
}

export default function DeviceCheckPage() {
  return (
    <Suspense>
      <DeviceCheck />
    </Suspense>
  );
}
