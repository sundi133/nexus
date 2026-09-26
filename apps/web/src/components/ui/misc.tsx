import * as React from "react";
import { cn, initials } from "@/lib/utils";

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-lg border border-border bg-bg shadow-card", className)} {...props} />;
}

export function CardHeader({ title, description, actions }: { title: React.ReactNode; description?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border px-4 py-3">
      <div>
        <h3 className="text-sm font-semibold">{title}</h3>
        {description ? <p className="mt-0.5 text-[13px] text-fg-muted">{description}</p> : null}
      </div>
      {actions}
    </div>
  );
}

const TONES = {
  neutral: "bg-bg-muted text-fg-muted",
  success: "bg-success-soft text-success",
  warning: "bg-warning-soft text-warning",
  danger: "bg-danger-soft text-danger",
  primary: "bg-primary-soft text-primary",
} as const;
export type Tone = keyof typeof TONES;

/** Status pill: dot + label, never color alone (a11y). */
export function StatusPill({ tone = "neutral", children, dot = true }: { tone?: Tone; children: React.ReactNode; dot?: boolean }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium", TONES[tone])}>
      {dot ? <span className="size-1.5 rounded-full bg-current" aria-hidden /> : null}
      {children}
    </span>
  );
}

export function Badge({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn("inline-flex items-center rounded border border-border bg-bg-subtle px-1.5 py-px text-[11px] font-medium text-fg-muted", className)}
      {...props}
    />
  );
}

export function Avatar({ name, size = 28 }: { name: string; size?: number }) {
  // Stable hue per name so the same person always looks the same.
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return (
    <span
      aria-hidden
      className="inline-flex shrink-0 items-center justify-center rounded-full text-[11px] font-semibold text-white"
      style={{ width: size, height: size, background: `hsl(${h} 55% 50%)`, fontSize: size * 0.38 }}
    >
      {initials(name) || "?"}
    </span>
  );
}

export function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-border bg-bg-subtle px-1 font-mono text-[11px] text-fg-muted">
      {children}
    </kbd>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-bg-muted", className)} />;
}

export function EmptyState({ icon, title, description, action }: { icon?: React.ReactNode; title: string; description?: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      {icon ? <div className="mb-3 rounded-full bg-bg-muted p-3 text-fg-muted [&_svg]:size-5">{icon}</div> : null}
      <p className="text-sm font-medium">{title}</p>
      {description ? <p className="mt-1 max-w-sm text-[13px] text-fg-muted">{description}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function PageHeader({ title, description, actions }: { title: React.ReactNode; description?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="mt-1 text-[13px] text-fg-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function KeyValue({ items }: { items: [string, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,auto)_1fr] gap-x-4 gap-y-2.5 text-[13px]">
      {items.map(([k, v]) => (
        <React.Fragment key={k}>
          <dt className="text-fg-muted">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof Error ? error.message : "Something went wrong";
  return <div className="rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-[13px] text-danger">{msg}</div>;
}
