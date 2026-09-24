"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { toast } from "sonner";
import { api, unwrap } from "./api";
import { qk } from "./queries";

/**
 * One live connection per tab to /v1/me/stream. Events only carry IDs, so we
 * invalidate the relevant queries and let them refetch through the API.
 */
export function useLiveUpdates() {
  const qc = useQueryClient();
  useEffect(() => {
    let es: EventSource | null = null;
    let retry = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let closed = false;

    const connect = () => {
      es = new EventSource("/bff/v1/me/stream");
      es.addEventListener("ready", () => {
        retry = 0;
      });
      es.addEventListener("notification", async (e) => {
        const { id, op } = JSON.parse((e as MessageEvent).data) as { id: string; op: string };
        await qc.invalidateQueries({ queryKey: qk.inbox });
        if (op !== "insert") return;
        // Surface security-relevant items as a toast too.
        const inbox = await qc.fetchQuery({
          queryKey: qk.inbox,
          queryFn: () => unwrap(api.GET("/v1/me/notifications", { params: { query: { limit: 30, filter: "all" } } })),
        });
        const n = inbox.data.find((x) => x.id === id);
        if (n && n.severity !== "info") {
          (n.severity === "critical" ? toast.error : toast.warning)(n.title, { description: n.body || undefined });
        }
        qc.invalidateQueries({ queryKey: qk.overview });
      });
      es.onerror = () => {
        es?.close();
        if (closed) return;
        retry = Math.min(retry + 1, 6);
        timer = setTimeout(connect, 500 * 2 ** retry); // exponential backoff up to ~30s
      };
    };
    connect();
    return () => {
      closed = true;
      clearTimeout(timer);
      es?.close();
    };
  }, [qc]);
}
