"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { Fingerprint, KeyRound, Smartphone } from "lucide-react";
import { PairPhone } from "./pair-phone";
import { QRCodeSVG } from "qrcode.react";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { passkeyErrorMessage, registerPasskey, usePasskeysSupported } from "@/lib/passkeys";
import { cn } from "@/lib/utils";

/** Choose and set up a factor. Passkeys are recommended: phishing-resistant and nothing to type. */
type Method = "passkey" | "push" | "totp";

export function MfaEnroll({ onDone, defaultMethod }: { onDone: () => void; defaultMethod?: Method }) {
  const supported = usePasskeysSupported();
  const [picked, setMethod] = useState<Method | null>(defaultMethod ?? null);
  const method = picked ?? (supported ? "passkey" : "totp");
  return (
    <div className="space-y-4">
      <div className="grid gap-2" role="radiogroup" aria-label="MFA method">
        <MethodCard
          active={method === "passkey"}
          disabled={!supported}
          onClick={() => setMethod("passkey")}
          icon={<Fingerprint />}
          title="Passkey"
          badge="Recommended"
          subtitle={supported ? "Touch ID, Windows Hello or a security key" : "Not supported in this browser"}
        />
        <MethodCard
          active={method === "push"}
          onClick={() => setMethod("push")}
          icon={<Smartphone />}
          title="Nexus Mobile"
          subtitle="Approve sign-ins with a tap"
        />
        <MethodCard
          active={method === "totp"}
          onClick={() => setMethod("totp")}
          icon={<KeyRound />}
          title="Authenticator app"
          subtitle="6-digit codes from any app"
        />
      </div>
      {method === "passkey" ? <PasskeyEnroll onDone={onDone} /> : method === "push" ? <PairPhone onDone={onDone} /> : <TotpEnroll onDone={onDone} />}
    </div>
  );
}

function MethodCard(props: { active: boolean; disabled?: boolean; onClick: () => void; icon: React.ReactNode; title: string; subtitle: string; badge?: string }) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={props.active}
      aria-label={`${props.title}: ${props.subtitle}`}
      disabled={props.disabled}
      onClick={props.onClick}
      className={cn(
        "flex items-center gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
        props.active ? "border-primary bg-primary-soft" : "border-border hover:bg-bg-subtle",
      )}
    >
      <span className={cn("flex size-4 shrink-0 items-center justify-center rounded-full border", props.active ? "border-primary" : "border-border-strong")} aria-hidden>
        {props.active ? <span className="size-2 rounded-full bg-primary" /> : null}
      </span>
      {props.icon}
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2 text-[13px] font-medium">
          {props.title}
          {props.badge ? <span className="rounded bg-primary px-1.5 text-[10px] font-semibold text-primary-fg">{props.badge}</span> : null}
        </span>
        <span className="block text-xs text-fg-muted">{props.subtitle}</span>
      </span>
    </button>
  );
}

function PasskeyEnroll({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("Passkey");
  useEffect(() => setName(defaultPasskeyName()), []);
  const add = useMutation({ mutationFn: () => registerPasskey(name), onSuccess: onDone, onError: () => {} });
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        add.mutate();
      }}
    >
      {add.error ? <ErrorBanner error={new Error(passkeyErrorMessage(add.error))} /> : null}
      <div>
        <label htmlFor="pk-name" className="mb-1 block text-[13px] font-medium">
          Name this passkey
        </label>
        <Input id="pk-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} />
      </div>
      <Button type="submit" variant="primary" size="lg" className="w-full" loading={add.isPending}>
        <Fingerprint /> Create passkey
      </Button>
      <p className="text-center text-xs text-fg-muted">Your device will ask for your fingerprint, face or PIN. Nothing biometric leaves your device.</p>
    </form>
  );
}

function TotpEnroll({ onDone }: { onDone: () => void }) {
  const [code, setCode] = useState("");
  const start = useQuery({
    queryKey: ["totp-enroll"],
    queryFn: () => unwrap(api.POST("/v1/me/factors/totp", { body: { name: "Authenticator app" } })),
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
  });
  const verify = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/me/factors/{id}/verify", { params: { path: { id: start.data!.id } }, body: { code } })),
    onSuccess: onDone,
    onError: () => setCode(""),
  });
  if (!start.data) return <ErrorBanner error={start.error} />;
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        verify.mutate();
      }}
    >
      <div className="flex justify-center rounded-lg border border-border bg-white p-4">
        <QRCodeSVG value={start.data.otpauth_url} size={160} />
      </div>
      <details className="text-xs text-fg-muted">
        <summary className="cursor-pointer">Can&apos;t scan? Enter the key manually</summary>
        <code className="mt-2 block break-all rounded bg-bg-subtle p-2 font-mono">{start.data.secret}</code>
      </details>
      <ErrorBanner error={verify.error} />
      <Input
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={6}
        placeholder="Enter the 6-digit code"
        value={code}
        onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
        className="h-10 text-center font-mono tracking-[0.4em]"
        aria-label="Verification code"
      />
      <Button type="submit" variant="primary" size="lg" className="w-full" disabled={code.length !== 6} loading={verify.isPending}>
        Verify and turn on
      </Button>
    </form>
  );
}

function defaultPasskeyName() {
  if (typeof navigator === "undefined") return "Passkey";
  const ua = navigator.userAgent;
  if (/iPhone|iPad/.test(ua)) return "iPhone";
  if (/Mac/.test(ua)) return "Mac";
  if (/Windows/.test(ua)) return "Windows Hello";
  if (/Android/.test(ua)) return "Android";
  return "Passkey";
}
