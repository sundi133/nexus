"use client";

import { useMutation } from "@tanstack/react-query";
import { Printer } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";

/** RBAC-05 actions for owners: designate an emergency account and issue its sealed password. */
export function useBreakGlass(userId: string, onChange: () => void) {
  const withStepUp = useStepUp();
  const [password, setPassword] = useState<string | null>(null);
  const designate = useMutation({
    mutationFn: (enabled: boolean) => withStepUp(() => unwrap(api.PUT("/v1/users/{id}/break-glass", { params: { path: { id: userId } }, body: { enabled } }))),
    onSuccess: (r) => {
      onChange();
      toast.success(r.break_glass ? "Designated as break-glass" : "No longer a break-glass account", {
        description: r.break_glass ? "Generate its sealed emergency password next." : undefined,
      });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Couldn't change that"),
  });
  const generate = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/users/{id}/break-glass/password", { params: { path: { id: userId } } }))),
    onSuccess: (r) => (setPassword(r.password), onChange()),
    onError: (err) => toast.error(err instanceof Error ? err.message : "Couldn't generate a password"),
  });
  const dialog = password ? (
    <Dialog open onOpenChange={(o) => !o && setPassword(null)}>
      <DialogContent title="Emergency password" description="Shown once. Print it, seal it in an envelope with the account's security key, and store it somewhere only owners can reach.">
        <p className="rounded-md border border-border bg-bg-subtle px-4 py-3 text-center font-mono text-lg tracking-wider">{password}</p>
        <p className="mt-2 text-xs text-fg-muted">Every sign-in with this account alerts all admins. It has been signed out everywhere.</p>
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => window.print()}>
            <Printer /> Print
          </Button>
          <Button variant="primary" onClick={() => setPassword(null)}>
            It&apos;s sealed
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  ) : null;
  return { designate, generate, dialog };
}
