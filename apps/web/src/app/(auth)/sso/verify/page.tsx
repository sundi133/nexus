"use client";

import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { MfaVerify } from "@/components/features/mfa-verify";
import { api, bffAuth, unwrap } from "@/lib/api";

/** An app's access policy requires MFA and this session hasn't done it yet: step up, then resume. */
function Verify() {
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") ?? "/";
  const app = params.get("app") ?? "This app";
  const session = useQuery({ queryKey: ["auth-session"], queryFn: () => unwrap(api.GET("/v1/auth/session")), retry: false });
  const restart = async () => {
    await bffAuth("logout").catch(() => undefined);
    router.replace(`/login?next=${encodeURIComponent(next)}`);
  };

  if (session.data && session.data.factors.length === 0) {
    return (
      <div className="space-y-4 text-center">
        <div className="mx-auto w-fit rounded-full bg-primary-soft p-2.5 text-primary">
          <ShieldCheck className="size-5" />
        </div>
        <h1 className="text-lg font-semibold">Set up a second factor</h1>
        <p className="text-[13px] text-fg-muted">{app} requires multi-factor authentication. Add an authenticator app, passkey or Nexus Mobile, then open the app again.</p>
        <Link href="/settings/security" className="inline-block text-[13px] font-medium text-primary hover:underline">
          Go to My security
        </Link>
      </div>
    );
  }
  return <MfaVerify next={next} onRestart={() => void restart()} subtitle={`${app} requires multi-factor authentication.`} />;
}

export default function VerifyPage() {
  return (
    <Suspense>
      <Verify />
    </Suspense>
  );
}
