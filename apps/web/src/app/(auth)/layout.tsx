import { Logo } from "@/components/logo";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center bg-bg-subtle px-4 py-10">
      <div className="mb-8">
        <Logo size={28} />
      </div>
      <div className="w-full max-w-sm rounded-lg border border-border bg-bg p-6 shadow-card">{children}</div>
      <p className="mt-6 text-xs text-fg-subtle">Identity, device and AI-agent security</p>
    </main>
  );
}
