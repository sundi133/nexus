"use client";

import { useQuery } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";
import { useEffect, useRef } from "react";
import { ErrorBanner } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";

/** Shows a one-time QR code for Nexus Mobile and finishes when the phone has paired. */
export function PairPhone({ onDone }: { onDone: () => void }) {
  const pairing = useQuery({
    queryKey: ["push-pairing"],
    queryFn: () => unwrap(api.POST("/v1/me/factors/push/pairing")),
    staleTime: 9 * 60_000,
    gcTime: 0,
    refetchOnWindowFocus: false,
  });
  const baseline = useRef<number | null>(null);
  const factors = useQuery({
    queryKey: ["factors", "pairing-watch"],
    queryFn: () => unwrap(api.GET("/v1/me/factors")),
    refetchInterval: 2000,
    enabled: !!pairing.data,
  });
  useEffect(() => {
    const n = factors.data?.data.filter((f) => f.type === "push" && f.verified).length;
    if (n === undefined) return;
    if (baseline.current === null) baseline.current = n;
    else if (n > baseline.current) onDone();
  }, [factors.data, onDone]);

  if (!pairing.data) return <ErrorBanner error={pairing.error} />;
  return (
    <div className="space-y-3 text-center">
      <ol className="space-y-1 text-left text-[13px] text-fg-muted">
        <li>1. Install <span className="font-medium text-fg">Nexus Mobile</span> on your phone.</li>
        <li>2. Tap <span className="font-medium text-fg">Pair with a QR code</span> and scan this.</li>
      </ol>
      <div className="flex justify-center rounded-lg border border-border bg-white p-4">
        <QRCodeSVG value={pairing.data.pairing_url} size={176} />
      </div>
      <p className="flex items-center justify-center gap-1.5 text-xs text-fg-subtle">
        <span className="size-2 animate-pulse rounded-full bg-primary" /> Waiting for your phone… (code valid for 10 minutes)
      </p>
      <details className="text-left text-xs text-fg-muted">
        <summary className="cursor-pointer">Can&apos;t scan? Enter the code in the app</summary>
        <code className="mt-2 block break-all rounded bg-bg-subtle p-2 font-mono">{pairing.data.code}</code>
      </details>
    </div>
  );
}
