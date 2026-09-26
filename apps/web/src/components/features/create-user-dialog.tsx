"use client";

import type { Role } from "@nexus/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, fieldErrors, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { ROLE_LABELS } from "@/lib/utils";

const empty = { email: "", given_name: "", family_name: "", title: "", department: "", password: "", role: "", mode: "invite" as "invite" | "password" };

export function CreateUserDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const router = useRouter();
  const can = useCan();
  const [form, setForm] = useState(empty);
  const set = (k: keyof typeof empty) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setForm({ ...form, [k]: e.target.value });

  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/v1/users", {
          body: {
            email: form.email,
            given_name: form.given_name,
            family_name: form.family_name,
            title: form.title,
            department: form.department,
            password: form.mode === "password" ? form.password : undefined,
            invite: form.mode === "invite",
            roles: form.role ? [form.role as Role] : [],
          },
        }),
      ),
    onSuccess: (u) => {
      qc.invalidateQueries({ queryKey: ["users"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
      toast.success(form.mode === "invite" ? `Invitation sent to ${u.email}` : `${u.display_name} was added`, {
        action: { label: "View", onClick: () => router.push(`/users/${u.id}`) },
      });
      setForm(empty);
      onOpenChange(false);
    },
    onError: () => {},
  });
  const errs = fieldErrors(create.error);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="Add a user" description="They'll get an email to set their password and join.">
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          {Object.keys(errs).length === 0 ? <ErrorBanner error={create.error} /> : null}
          <div className="grid grid-cols-2 gap-3">
            <Field label="First name" htmlFor="u-gn" error={errs.given_name}>
              <Input id="u-gn" required autoFocus value={form.given_name} onChange={set("given_name")} />
            </Field>
            <Field label="Last name" htmlFor="u-fn" error={errs.family_name}>
              <Input id="u-fn" value={form.family_name} onChange={set("family_name")} />
            </Field>
          </div>
          <Field label="Work email" htmlFor="u-email" error={errs.email}>
            <Input id="u-email" type="email" required value={form.email} onChange={set("email")} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Title" htmlFor="u-title">
              <Input id="u-title" value={form.title} onChange={set("title")} />
            </Field>
            <Field label="Department" htmlFor="u-dept">
              <Input id="u-dept" value={form.department} onChange={set("department")} />
            </Field>
          </div>
          <fieldset className="space-y-2">
            <legend className="mb-1 text-[13px] font-medium">How will they sign in?</legend>
            <label className="flex items-center gap-2 text-[13px]">
              <input type="radio" name="mode" checked={form.mode === "invite"} onChange={() => setForm({ ...form, mode: "invite" })} />
              Email an invitation <span className="text-fg-subtle">(recommended)</span>
            </label>
            <label className="flex items-center gap-2 text-[13px]">
              <input type="radio" name="mode" checked={form.mode === "password"} onChange={() => setForm({ ...form, mode: "password" })} />
              Set a temporary password
            </label>
          </fieldset>
          {form.mode === "password" ? (
            <Field label="Temporary password" htmlFor="u-pw" hint="At least 12 characters. Share it securely." error={errs.password}>
              <Input id="u-pw" type="password" autoComplete="new-password" required value={form.password} onChange={set("password")} />
            </Field>
          ) : null}
          {can("admins:manage") ? (
            <Field label="Admin role" htmlFor="u-role" hint="Leave as Member unless they administer Nexus.">
              <Select id="u-role" value={form.role} onChange={set("role")} className="w-full">
                <option value="">Member (no admin access)</option>
                {Object.entries(ROLE_LABELS).map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </Select>
            </Field>
          ) : null}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={create.isPending}>
              {form.mode === "invite" ? "Send invitation" : "Create user"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
