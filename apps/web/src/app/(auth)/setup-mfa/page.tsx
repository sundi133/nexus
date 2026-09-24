"use client";

import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect } from "react";
import { MfaEnroll } from "@/components/features/mfa-enroll";
import { api, bffAuth, goTo, unwrap } from "@/lib/api";

function SetupMfa() {
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") ?? "/";
  const session = useQuery({ queryKey: ["auth-session"], queryFn: () => unwrap(api.GET("/v1/auth/session")), retry: false });

  useEffect(() => {
    if (session.data?.state === "active") goTo(next.startsWith("/") && !next.startsWith("//") ? next : "/", router);
  }, [session.data?.state, next, router]);

  return (
    <div className="space-y-5">
      <div className="flex flex-col items-center text-center">
        <div className="mb-3 rounded-full bg-primary-soft p-2.5 text-primary">
          <ShieldCheck className="size-5" />
        </div>
        <h1 className="text-lg font-semibold">Secure your account</h1>
        <p className="mt-1 text-[13px] text-fg-muted">
          {session.data ? `${session.data.organization_name} requires` : "Your organization requires"} a second step when you sign in. It takes a minute.
        </p>
        {session.data ? <p className="mt-1 text-xs text-fg-subtle">{session.data.email}</p> : null}
      </div>
      <MfaEnroll onDone={() => goTo(next.startsWith("/") && !next.startsWith("//") ? next : "/", router)} />
      <button
        type="button"
        className="block w-full text-center text-[13px] text-fg-muted hover:text-fg"
        onClick={async () => {
          await bffAuth("logout");
          router.replace("/login");
        }}
      >
        Sign out
      </button>
    </div>
  );
}

export default function SetupMfaPage() {
  return (
    <Suspense>
      <SetupMfa />
    </Suspense>
  );
}
