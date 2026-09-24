"use client";

import { useQuery } from "@tanstack/react-query";
import { AppWindow, Plus, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { AddAppDialog } from "@/components/features/add-app-dialog";
import { AppIcon } from "@/components/features/app-icon";
import { Button } from "@/components/ui/button";
import { Badge, Card, EmptyState, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { pluralize } from "@/lib/utils";

export default function AppsPage() {
  const router = useRouter();
  const can = useCan();
  const [creating, setCreating] = useState(false);
  const apps = useQuery({ queryKey: ["apps"], queryFn: () => unwrap(api.GET("/v1/apps")) });

  return (
    <>
      <PageHeader
        title="Applications"
        description="Apps your people sign in to with Nexus. Only assigned users and groups can use each app."
        actions={
          can("apps:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus /> Add app
            </Button>
          ) : null
        }
      />
      <Card className="overflow-hidden">
        {apps.isPending ? (
          <Skeleton className="m-4 h-24" />
        ) : !apps.data?.data.length ? (
          <EmptyState
            icon={<AppWindow />}
            title="No applications yet"
            description="Connect an app over OpenID Connect so your team signs in with Nexus, including MFA and device checks."
            action={can("apps:write") ? <Button onClick={() => setCreating(true)}>Add your first app</Button> : undefined}
          />
        ) : (
          <Table>
            <THead>
              <tr>
                <TH>Application</TH>
                <TH>Protocol</TH>
                <TH>Access</TH>
                <TH>Status</TH>
              </tr>
            </THead>
            <tbody>
              {apps.data.data.map((a) => (
                <TR key={a.id} className="cursor-pointer" onClick={() => router.push(`/apps/${a.id}`)}>
                  <TD>
                    <Link href={`/apps/${a.id}`} className="flex items-center gap-3" onClick={(e) => e.stopPropagation()}>
                      <AppIcon name={a.name} size={30} />
                      <span className="font-medium">{a.name}</span>
                    </Link>
                  </TD>
                  <TD>
                    <Badge>{a.protocol.toUpperCase()}</Badge>
                  </TD>
                  <TD className="text-fg-muted">
                    {a.assignment_count ? (
                      pluralize(a.assignment_count, "assignment")
                    ) : (
                      <span className="inline-flex items-center gap-1 text-warning">
                        <TriangleAlert className="size-3.5" /> Nobody assigned
                      </span>
                    )}
                  </TD>
                  <TD>{a.status === "active" ? <StatusPill tone="success">Active</StatusPill> : <StatusPill>Disabled</StatusPill>}</TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <AddAppDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}

