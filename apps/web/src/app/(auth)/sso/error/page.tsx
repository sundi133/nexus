import { ShieldAlert } from "lucide-react";
import Link from "next/link";

export default async function SsoErrorPage({ searchParams }: { searchParams: Promise<{ title?: string; message?: string }> }) {
  const { title, message } = await searchParams;
  return (
    <div className="space-y-4 text-center">
      <div className="mx-auto w-fit rounded-full bg-warning-soft p-2.5 text-warning">
        <ShieldAlert className="size-5" />
      </div>
      <h1 className="text-lg font-semibold">{title ?? "Sign-in couldn't continue"}</h1>
      {message ? <p className="text-[13px] text-fg-muted">{message}</p> : null}
      <Link href="/my-apps" className="inline-block text-[13px] font-medium text-primary hover:underline">
        Go to my apps
      </Link>
    </div>
  );
}
