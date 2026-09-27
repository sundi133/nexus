"use client";

import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "./api";
import type { Permission } from "@nexus/api-client";

export const qk = {
  me: ["me"] as const,
  overview: ["overview"] as const,
  inbox: ["inbox"] as const,
  users: (params: Record<string, string | undefined>) => ["users", params] as const,
  user: (id: string) => ["user", id] as const,
  groups: (q?: string) => ["groups", q ?? ""] as const,
  group: (id: string) => ["group", id] as const,
  groupMembers: (id: string) => ["group", id, "members"] as const,
  audit: (params: Record<string, string | undefined>) => ["audit", params] as const,
  factors: ["factors"] as const,
  sessions: ["sessions"] as const,
};

export function useMe() {
  return useQuery({ queryKey: qk.me, queryFn: () => unwrap(api.GET("/v1/me")), staleTime: 60_000 });
}

/** Can the signed-in person do this anywhere? Scoped roles count: the server limits them to their groups. */
export function useCan() {
  const { data } = useMe();
  const perms = new Set<Permission>([...(data?.permissions ?? []), ...(Object.keys(data?.scoped_permissions ?? {}) as Permission[])]);
  return (p: Permission) => perms.has(p);
}

export function useInbox() {
  return useQuery({
    queryKey: qk.inbox,
    queryFn: () => unwrap(api.GET("/v1/me/notifications", { params: { query: { limit: 30, filter: "all" } } })),
  });
}
