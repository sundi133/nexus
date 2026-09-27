import { ShieldAlert } from "lucide-react";
import Link from "next/link";

export default async function SsoErrorPage({ searchParams }: { searchParams: Promise<{ title?: string; message?: string; code?: string }> }) {
  const { title, message, code } = await searchParams;
  // Device-related blocks can usually be fixed by the user: point them at their devices.
  const deviceIssue = code === "access_denied" && /device|compliant|report/i.test(message ?? "");
  return (
    <div className="space-y-4 text-center">
      <div className="mx-auto w-fit rounded-full bg-warning-soft p-2.5 text-warning">
        <ShieldAlert className="size-5" />
      </div>
      <h1 className="text-lg font-semibold">{title ?? "Sign-in couldn't continue"}</h1>
      {message ? <p className="text-[13px] text-fg-muted">{message}</p> : null}
      <div className="flex flex-col gap-2">
        {deviceIssue ? (
          <Link href="/my-devices" className="inline-flex h-9 items-center justify-center rounded-md bg-primary px-4 text-[13px] font-medium text-primary-fg shadow-card hover:opacity-90">
            See what to fix
          </Link>
        ) : null}
        <Link href="/my-apps" className="inline-block text-[13px] font-medium text-primary hover:underline">
          Go to my apps
        </Link>
      </div>
    </div>
  );
}
