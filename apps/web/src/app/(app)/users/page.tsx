"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { FileUp, Plus, Search, Users as UsersIcon, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { CreateUserDialog } from "@/components/features/create-user-dialog";
import { ImportUsersDialog } from "@/components/features/import-users-dialog";
import { MfaBadge, RoleBadges, UserStatusPill } from "@/components/features/user-bits";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import { Avatar, Card, EmptyState, PageHeader, Skeleton } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

type Status = "active" | "staged" | "suspended" | "deprovisioned";
type RoleFilter = "any_admin" | "owner" | "admin" | "helpdesk" | "security_analyst" | "readonly";

function UsersView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const can = useCan();
  const [q, setQ] = useState(params.get("q") ?? "");
  const filters = {
    q: params.get("q") ?? undefined,
    status: (params.get("status") as Status) ?? undefined,
    mfa: (params.get("mfa") as "enrolled" | "missing") ?? undefined,
    role: (params.get("role") as RoleFilter) ?? undefined,
  };

  // Filters live in the URL so views are shareable and survive reloads (docs/UI.md §4.1).
  const setParam = (k: string, v: string | undefined) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    router.replace(`${pathname}?${next}`);
  };

  useEffect(() => {
    const t = setTimeout(() => {
      if ((params.get("q") ?? "") !== q) setParam("q", q || undefined);
    }, 250);
    return () => clearTimeout(t);
  }, [q]);

  const query = useInfiniteQuery({
    queryKey: ["users", filters],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => unwrap(api.GET("/v1/users", { params: { query: { ...filters, cursor: pageParam, limit: 50 } } })),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const users = query.data?.pages.flatMap((p) => p.data) ?? [];
  const activeFilters = Object.entries(filters).filter(([k, v]) => v && k !== "q");

  return (
    <>
      <PageHeader
        title="Users"
        description="Everyone in your directory. Filters are saved in the URL."
        actions={
          can("users:write") ? (
            <>
              <Button onClick={() => setParam("import", "1")}>
                <FileUp /> Import CSV
              </Button>
              <Button variant="primary" onClick={() => setParam("new", "1")}>
                <Plus /> Add user
              </Button>
            </>
          ) : null
        }
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative w-full max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-2 size-4 text-fg-subtle" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name or email" className="pl-8" aria-label="Search users" />
        </div>
        <Select value={filters.status ?? ""} onChange={(e) => setParam("status", e.target.value || undefined)} aria-label="Status">
          <option value="">Any status</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
          <option value="staged">Invited</option>
        </Select>
        <Select value={filters.mfa ?? ""} onChange={(e) => setParam("mfa", e.target.value || undefined)} aria-label="MFA">
          <option value="">Any MFA</option>
          <option value="enrolled">MFA enrolled</option>
          <option value="missing">No MFA</option>
        </Select>
        <Select value={filters.role ?? ""} onChange={(e) => setParam("role", e.target.value || undefined)} aria-label="Role">
          <option value="">Any role</option>
          <option value="any_admin">Any admin</option>
          <option value="owner">Owner</option>
          <option value="admin">Admin</option>
          <option value="helpdesk">Help desk</option>
          <option value="security_analyst">Security analyst</option>
          <option value="readonly">Read-only</option>
        </Select>
        {activeFilters.length ? (
          <Button variant="ghost" size="sm" onClick={() => router.replace(pathname)}>
            <X /> Clear
          </Button>
        ) : null}
      </div>

      <Card className="overflow-hidden">
        {query.isPending ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-9" />
            ))}
          </div>
        ) : users.length === 0 ? (
          <EmptyState
            icon={<UsersIcon />}
            title={filters.q || activeFilters.length ? "No users match these filters" : "No users yet"}
            description={filters.q || activeFilters.length ? "Try clearing a filter." : "Add your teammates to start managing their access."}
          />
        ) : (
          <Table>
            <THead>
              <tr>
                <TH>Name</TH>
                <TH>Status</TH>
                <TH>MFA</TH>
                <TH className="hidden md:table-cell">Admin roles</TH>
                <TH className="hidden lg:table-cell">Department</TH>
                <TH className="text-right">Last sign-in</TH>
              </tr>
            </THead>
            <tbody>
              {users.map((u) => (
                <TR key={u.id} className="cursor-pointer" onClick={() => router.push(`/users/${u.id}`)}>
                  <TD>
                    <Link href={`/users/${u.id}`} className="flex items-center gap-2.5" onClick={(e) => e.stopPropagation()}>
                      <Avatar name={u.display_name} />
                      <span className="min-w-0">
                        <span className="block truncate font-medium">{u.display_name}</span>
                        <span className="block truncate text-xs text-fg-muted">
                          {u.email}
                          {u.managed_by ? <span className="ml-1.5 text-fg-subtle">· synced from {u.managed_by}</span> : null}
                        </span>
                      </span>
                    </Link>
                  </TD>
                  <TD>
                    <UserStatusPill status={u.status} />
                  </TD>
                  <TD>
                    <MfaBadge enrolled={u.mfa_enrolled} />
                  </TD>
                  <TD className="hidden md:table-cell">
                    <RoleBadges roles={u.roles} />
                  </TD>
                  <TD className="hidden text-fg-muted lg:table-cell">{u.department || "—"}</TD>
                  <TD className="text-right text-fg-muted tabular">{timeAgo(u.last_login_at)}</TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
        {query.hasNextPage ? (
          <div className="border-t border-border p-2 text-center">
            <Button variant="ghost" size="sm" onClick={() => query.fetchNextPage()} loading={query.isFetchingNextPage}>
              Load more
            </Button>
          </div>
        ) : null}
      </Card>
      <CreateUserDialog open={params.get("new") === "1"} onOpenChange={(v) => setParam("new", v ? "1" : undefined)} />
      <ImportUsersDialog open={params.get("import") === "1"} onOpenChange={(v) => setParam("import", v ? "1" : undefined)} />
    </>
  );
}

export default function UsersPage() {
  return (
    <Suspense>
      <UsersView />
    </Suspense>
  );
}
