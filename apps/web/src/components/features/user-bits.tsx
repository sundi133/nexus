import type { User } from "@nexus/api-client";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge, StatusPill, type Tone } from "@/components/ui/misc";
import { ROLE_LABELS } from "@/lib/utils";

const STATUS: Record<User["status"], { tone: Tone; label: string }> = {
  active: { tone: "success", label: "Active" },
  staged: { tone: "primary", label: "Invited" },
  suspended: { tone: "danger", label: "Suspended" },
  deprovisioned: { tone: "neutral", label: "Deprovisioned" },
};

export const UserStatusPill = ({ status }: { status: User["status"] }) => (
  <StatusPill tone={STATUS[status].tone}>{STATUS[status].label}</StatusPill>
);

export const MfaBadge = ({ enrolled }: { enrolled: boolean }) =>
  enrolled ? (
    <span className="inline-flex items-center gap-1 text-[13px] text-success">
      <ShieldCheck className="size-3.5" /> Enrolled
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-[13px] text-warning">
      <ShieldAlert className="size-3.5" /> None
    </span>
  );

export const RoleBadges = ({ roles }: { roles: string[] }) =>
  roles.length ? (
    <span className="flex flex-wrap gap-1">
      {roles.map((r) => (
        <Badge key={r}>{ROLE_LABELS[r] ?? r}</Badge>
      ))}
    </span>
  ) : (
    <span className="text-fg-subtle">—</span>
  );
