"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Laptop, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, ErrorBanner } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { qk } from "@/lib/queries";
import { passkeyErrorMessage, setUpDeviceSignIn, usePasskeysSupported } from "@/lib/passkeys";

/** Sign in with a managed computer: no email or password, just Touch ID or Windows Hello there. */
export function DeviceSignInCard() {
  const qc = useQueryClient();
  const supported = usePasskeysSupported();
  const list = useQuery({ queryKey: ["device-sign-in"], queryFn: () => unwrap(api.GET("/v1/me/device-sign-in")) });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["device-sign-in"] });
    qc.invalidateQueries({ queryKey: qk.factors });
  };
  const setUp = useMutation({
    mutationFn: setUpDeviceSignIn,
    onSuccess: (r) => (refresh(), toast.success(`You can now sign in with ${r.device.hostname}`, { description: "On the sign-in page, choose Sign in with this computer." })),
    onError: () => undefined,
  });
  const remove = useMutation({ mutationFn: (id: string) => unwrap(api.DELETE("/v1/me/device-sign-in/{factor_id}", { params: { path: { factor_id: id } } })), onSuccess: refresh });
  return (
    <Card>
      <CardHeader
        title="Sign in with this computer"
        description="On your work computer, sign in without typing your email or password: the Nexus agent vouches for the computer, and Touch ID or Windows Hello for you. It works only on that computer, while it's assigned to you and meets your organization's policies."
        actions={
          supported ? (
            <Button size="sm" loading={setUp.isPending} onClick={() => setUp.mutate()}>
              <Laptop /> Set up on this computer
            </Button>
          ) : null
        }
      />
      <div className="space-y-2 px-4 pb-4 text-[13px]">
        {setUp.error ? <ErrorBanner error={new Error(passkeyErrorMessage(setUp.error))} /> : null}
        <ErrorBanner error={list.error ?? remove.error} />
        {list.data?.data.length ? (
          <ul className="divide-y divide-border rounded-md border border-border">
            {list.data.data.map((b) => (
              <li key={b.factor_id} className="flex items-center gap-2 px-3 py-2">
                <Laptop className="size-4 text-fg-muted" />
                <span className="flex-1">{b.device.hostname}</span>
                <Button size="icon" variant="ghost" aria-label={`Stop signing in with ${b.device.hostname}`} onClick={() => remove.mutate(b.factor_id)}>
                  <Trash2 />
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-fg-muted">Not set up on any computer yet.</p>
        )}
      </div>
    </Card>
  );
}
