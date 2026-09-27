import type { Schemas } from "@nexus/api-client";
import { KeyRound } from "lucide-react";
import { Badge, StatusPill, type Tone } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";

type Governance = Schemas["DeviceMcpServer"]["governance"];

export const GOVERNANCE: Record<Governance, { label: string; tone: Tone; help: string }> = {
  bypass: { label: "Bypasses gateway", tone: "danger", help: "Connects straight to a server your organization put behind the Nexus gateway" },
  remote: { label: "Ungoverned", tone: "warning", help: "A remote MCP server that isn't behind the Nexus gateway" },
  allowed: { label: "Allowed host", tone: "neutral", help: "A remote host your device policy allows" },
  local: { label: "Local", tone: "neutral", help: "Runs on the device itself (stdio)" },
  gateway: { label: "Via Nexus", tone: "success", help: "Goes through the Nexus MCP gateway: policy and audit apply" },
};

export function GovernancePill({ governance, via }: { governance: Governance; via?: string | null }) {
  const g = GOVERNANCE[governance];
  return (
    <span title={via ? `${g.help} (${via})` : g.help}>
      <StatusPill tone={g.tone}>{g.label}</StatusPill>
    </span>
  );
}

export function SecretFlag() {
  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-danger" title="A token or key is written into this MCP config file in plain text">
      <KeyRound className="size-3.5" aria-hidden /> Token in config
    </span>
  );
}

/** A device's MCP servers, worst first. */
export function DeviceServers({ servers }: { servers: Schemas["DeviceMcpServer"][] }) {
  const rank: Record<Governance, number> = { bypass: 0, remote: 1, allowed: 2, local: 3, gateway: 4 };
  const rows = [...servers].sort((a, b) => Number(a.disabled) - Number(b.disabled) || rank[a.governance] - rank[b.governance] || a.name.localeCompare(b.name));
  return (
    <Table>
      <THead>
        <tr>
          <TH>Server</TH>
          <TH>Connects to</TH>
          <TH>Client</TH>
          <TH>Status</TH>
        </tr>
      </THead>
      <tbody>
        {rows.map((s) => (
          <TR key={`${s.user}-${s.client}-${s.scope}-${s.name}`} className={s.disabled ? "opacity-60" : undefined}>
            <TD>
              <span className="font-medium">{s.name}</span>
              {s.scope === "project" ? <Badge className="ml-1.5">project</Badge> : null}
              {s.disabled ? <Badge className="ml-1.5">disabled</Badge> : null}
            </TD>
            <TD>
              <code className="font-mono text-xs">{s.target || "—"}</code>
              {s.transport === "stdio" ? <span className="ml-1.5 text-xs text-fg-subtle">runs locally</span> : null}
              {s.env_keys.length ? <p className="mt-0.5 text-xs text-fg-subtle">env: {s.env_keys.slice(0, 4).join(", ")}{s.env_keys.length > 4 ? ` +${s.env_keys.length - 4}` : ""}</p> : null}
            </TD>
            <TD className="text-fg-muted">
              {s.client}
              <span className="text-fg-subtle"> · {s.user}</span>
            </TD>
            <TD>
              <div className="flex flex-col items-start gap-1">
                <GovernancePill governance={s.governance} via={s.via} />
                {s.inline_secrets ? <SecretFlag /> : null}
              </div>
            </TD>
          </TR>
        ))}
      </tbody>
    </Table>
  );
}

export const TOOL_KIND = { app: "App", cli: "CLI", extension: "Extension" } as const;
