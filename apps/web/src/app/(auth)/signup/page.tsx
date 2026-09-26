"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { bffAuth, fieldErrors } from "@/lib/api";

export default function SignupPage() {
  const router = useRouter();
  const [form, setForm] = useState({ organization_name: "", given_name: "", family_name: "", email: "", password: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const errs = fieldErrors(error);
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await bffAuth("signup", form);
      router.replace("/?welcome=1");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Create your organization</h1>
        <p className="mt-1 text-[13px] text-fg-muted">You&apos;ll be the owner. It takes about a minute.</p>
      </div>
      {Object.keys(errs).length === 0 ? <ErrorBanner error={error} /> : null}
      <Field label="Organization name" htmlFor="org" error={errs.organization_name}>
        <Input id="org" required autoFocus value={form.organization_name} onChange={set("organization_name")} placeholder="Acme Inc." />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="First name" htmlFor="gn" error={errs.given_name}>
          <Input id="gn" required autoComplete="given-name" value={form.given_name} onChange={set("given_name")} />
        </Field>
        <Field label="Last name" htmlFor="fn" error={errs.family_name}>
          <Input id="fn" autoComplete="family-name" value={form.family_name} onChange={set("family_name")} />
        </Field>
      </div>
      <Field label="Work email" htmlFor="email" error={errs.email}>
        <Input id="email" type="email" required autoComplete="username" value={form.email} onChange={set("email")} />
      </Field>
      <Field label="Password" htmlFor="pw" hint="At least 12 characters. A passphrase works well." error={errs.password}>
        <Input id="pw" type="password" required minLength={12} autoComplete="new-password" value={form.password} onChange={set("password")} />
      </Field>
      <Button type="submit" variant="primary" size="lg" className="w-full" loading={busy}>
        Create organization
      </Button>
      <p className="text-center text-[13px] text-fg-muted">
        Already have an account?{" "}
        <Link href="/login" className="font-medium text-primary hover:underline">
          Sign in
        </Link>
      </p>
    </form>
  );
}
