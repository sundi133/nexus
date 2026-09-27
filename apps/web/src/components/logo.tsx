export function Logo({ size = 22, withText = true }: { size?: number; withText?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2">
      <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden>
        <rect width="24" height="24" rx="6" fill="var(--primary)" />
        <path d="M7 17V7l10 10V7" stroke="var(--primary-fg)" strokeWidth="2.2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {withText ? (
        <span className="text-[15px] font-semibold tracking-tight">
          Votal <span className="text-fg-muted">Nexus</span>
        </span>
      ) : null}
    </span>
  );
}
