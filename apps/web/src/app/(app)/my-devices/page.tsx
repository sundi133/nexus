"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Laptop, Plus } from "lucide-react";
import { useState } from "react";
import { CheckList, ComplianceBadge, OnlineDot, PLATFORM_LABEL, PlatformIcon } from "@/components/features/device-bits";
import { EnrollInstructions } from "@/components/features/enroll-instructions";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, EmptyState, PageHeader, Skeleton } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { timeAgo } from "@/lib/utils";

/** Every employee's view of their own devices and what to fix (SPEC PORT-03). */
export default function MyDevicesPage() {
  const devices = useQuery({ queryKey: ["my-devices"], queryFn: () => unwrap(api.GET("/v1/me/devices")), refetchInterval: 30_000 });
  const [install, setInstall] = useState<Schemas["EnrollmentInstructions"] | null>(null);
  const enroll = useMutation({ mutationFn: () => unwrap(api.POST("/v1/me/devices/enrollment-token")), onSuccess: setInstall });

  return (
    <>
      <PageHeader
        title="My devices"
        description="Your computers managed by Nexus, and anything that needs fixing to keep access to work apps."
        actions={
          <Button onClick={() => enroll.mutate()} loading={enroll.isPending}>
            <Plus /> Enroll a computer
          </Button>
        }
      />
      {devices.isPending ? (
        <Skeleton className="h-40" />
      ) : !devices.data?.data.length ? (
        <Card>
          <EmptyState icon={<Laptop />} title="No devices yet" description="Enroll your work computer so Nexus can confirm it's secure." action={<Button onClick={() => enroll.mutate()}>Enroll a computer</Button>} />
        </Card>
      ) : (
        <div className="space-y-4">
          {devices.data.data.map((d) => (
            <Card key={d.id} className="overflow-hidden">
              <CardHeader
                title={
                  <span className="flex items-center gap-2">
                    <PlatformIcon platform={d.platform} /> {d.hostname} <ComplianceBadge compliance={d.compliance} graceUntil={d.compliance_grace_until} />
                  </span>
                }
                description={
                  <span className="inline-flex items-center gap-1.5">
                    <OnlineDot online={d.online} /> {d.online ? "Online" : `Last seen ${timeAgo(d.last_seen_at)}`} · {PLATFORM_LABEL[d.platform]} {d.os_version}
                  </span>
                }
              />
              <CheckList checks={d.checks} />
            </Card>
          ))}
        </div>
      )}
      <Dialog open={!!install} onOpenChange={(v) => !v && setInstall(null)}>
        <DialogContent title="Enroll your computer" description="This one-time token works for 24 hours and assigns the device to you." className="max-w-lg">
          {install ? <EnrollInstructions install={install} /> : null}
        </DialogContent>
      </Dialog>
    </>
  );
}
