"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Card, ErrorBanner, PageHeader } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";

/** Google sends the admin back here after creating the Android enterprise, with a one-time token. */
export default function AndroidConnectedPage() {
  return (
    <Suspense>
      <Finish />
    </Suspense>
  );
}

function Finish() {
  const params = useSearchParams();
  const router = useRouter();
  const withStepUp = useStepUp();
  const token = params.get("enterpriseToken") ?? "";
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const started = useRef(false);
  const finish = async () => {
    setBusy(true);
    setError(null);
    try {
      await withStepUp(() => unwrap(api.POST("/v1/android/enterprise", { body: { enterprise_token: token } })));
      router.replace("/android");
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    if (started.current || !token) return;
    started.current = true;
    void finish();
  }, [token]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <>
      <PageHeader title="Connecting Android Enterprise" />
      <Card className="max-w-lg space-y-3 p-5 text-[13px]">
        {!token ? <p>Google didn&apos;t send an enterprise token. Start again from Android → Connect to Google.</p> : busy ? <p>Creating your Android enterprise…</p> : null}
        <ErrorBanner error={error} />
        {error ? (
          <Button variant="primary" onClick={() => void finish()}>
            Try again
          </Button>
        ) : null}
      </Card>
    </>
  );
}
