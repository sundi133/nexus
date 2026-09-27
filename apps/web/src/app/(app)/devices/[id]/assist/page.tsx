"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Eye, Hand, Maximize2, MonitorPlay, PhoneOff, RefreshCw } from "lucide-react";
import Link from "next/link";
import { use, useEffect, useRef, useState } from "react";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { formatDateTime, timeAgo } from "@/lib/utils";

type Session = Schemas["RemoteAssistSession"];
type RFBType = InstanceType<typeof import("@novnc/novnc").default>;

const TONE: Record<Session["status"], { tone: Tone; label: string }> = {
  asking: { tone: "warning", label: "Waiting for approval" },
  active: { tone: "success", label: "Active" },
  declined: { tone: "neutral", label: "Declined" },
  ended: { tone: "neutral", label: "Ended" },
  expired: { tone: "neutral", label: "No answer" },
  failed: { tone: "danger", label: "Failed" },
};

/** Remote Assist: see (and control) a Mac's screen once the person at it allows it. */
export default function RemoteAssistPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const device = useQuery({ queryKey: ["device", id], queryFn: () => unwrap(api.GET("/v1/devices/{id}", { params: { path: { id } } })) });
  const sessions = useQuery({
    queryKey: ["remote-assist", id],
    queryFn: () => unwrap(api.GET("/v1/devices/{id}/remote-assist", { params: { path: { id } } })),
    refetchInterval: (q) => (q.state.data?.data.some((s) => s.status === "asking") ? 2000 : q.state.data?.data.some((s) => s.status === "active") ? 10_000 : false),
  });
  const current = sessions.data?.data.find((s) => s.status === "asking" || s.status === "active");
  const refresh = () => qc.invalidateQueries({ queryKey: ["remote-assist", id] });
  const end = useMutation({ mutationFn: (sid: string) => unwrap(api.POST("/v1/remote-assist/sessions/{id}/end", { params: { path: { id: sid } } })), onSuccess: refresh });
  const hostname = device.data?.hostname ?? "…";

  return (
    <>
      <Link href={`/devices/${id}`} className="mb-3 inline-flex items-center gap-1 text-[13px] text-fg-muted hover:text-fg">
        <ArrowLeft className="size-3.5" /> {hostname}
      </Link>
      <PageHeader
        title="Remote Assist"
        description={`See and control ${hostname}'s screen to help the person using it. They're asked first, can end it at any time, and everything is in the audit log.`}
        actions={current ? <Button variant="danger-outline" loading={end.isPending} onClick={() => end.mutate(current.id)}><PhoneOff /> {current.status === "asking" ? "Withdraw request" : "End session"}</Button> : null}
      />
      <ErrorBanner error={device.error ?? sessions.error ?? end.error} />
      {device.isPending || sessions.isPending ? (
        <Skeleton className="h-40" />
      ) : device.data && device.data.platform === "linux" ? (
        <EmptyState icon={<MonitorPlay />} title="Macs and Windows PCs for now" description="Remote Assist works on Macs and Windows PCs running the Nexus agent. Linux is on the roadmap." />
      ) : !current ? (
        <RequestForm deviceId={id} online={!!device.data?.online} onAsked={refresh} withStepUp={withStepUp} />
      ) : current.status === "asking" ? (
        <Card className="p-5">
          <p className="text-sm font-medium">Waiting for the person at {hostname} to allow it…</p>
          <p className="mt-1 text-[13px] text-fg-muted">
            They'll see who you are and your reason: “{current.reason}”. The request expires {timeAgo(current.expires_at)}.
          </p>
        </Card>
      ) : current.mine ? (
        <Viewer session={current} />
      ) : (
        <Card className="p-5 text-[13px]">
          {current.requested_by} is helping on {hostname}. The person there allowed them, so only they can view it.
        </Card>
      )}

      <Card className="mt-5 overflow-hidden">
        <CardHeader title="Recent sessions" />
        {sessions.data?.data.length ? (
          <Table>
            <THead>
              <TR>
                <TH>When</TH>
                <TH>By</TH>
                <TH>Reason</TH>
                <TH>Outcome</TH>
              </TR>
            </THead>
            <tbody>
              {sessions.data.data.map((s) => (
                <TR key={s.id}>
                  <TD className="whitespace-nowrap">{formatDateTime(s.created_at)}</TD>
                  <TD>{s.requested_by ?? "—"}</TD>
                  <TD className="max-w-xs truncate">{s.reason}</TD>
                  <TD>
                    <StatusPill tone={TONE[s.status].tone}>{TONE[s.status].label}</StatusPill>
                    {s.detail ? <span className="ml-2 text-xs text-fg-muted">{s.detail}</span> : null}
                  </TD>
                </TR>
              ))}
            </tbody>
          </Table>
        ) : (
          <p className="px-4 pb-4 text-[13px] text-fg-muted">None yet.</p>
        )}
      </Card>
    </>
  );
}

function RequestForm({ deviceId, online, onAsked, withStepUp }: { deviceId: string; online: boolean; onAsked: () => void; withStepUp: ReturnType<typeof useStepUp> }) {
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState(60);
  const ask = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/devices/{id}/remote-assist", { params: { path: { id: deviceId } }, body: { reason, minutes } }))),
    onSuccess: onAsked,
  });
  return (
    <Card className="max-w-lg p-5">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          ask.mutate();
        }}
      >
        <Field label="Why do you need to see the screen?" htmlFor="ra-reason" hint="The person at the Mac sees this with your name before they decide.">
          <Input id="ra-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Fixing the VPN connection (ticket 4312)" autoFocus />
        </Field>
        <Field label="For up to" htmlFor="ra-minutes">
          <Select id="ra-minutes" value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
            {[15, 30, 60, 120].map((m) => (
              <option key={m} value={m}>
                {m < 60 ? `${m} minutes` : `${m / 60} hour${m > 60 ? "s" : ""}`}
              </option>
            ))}
          </Select>
        </Field>
        <ErrorBanner error={ask.error} />
        <Button type="submit" variant="primary" loading={ask.isPending} disabled={reason.trim().length < 3 || !online}>
          <MonitorPlay /> Ask to see the screen
        </Button>
        {!online ? <p className="text-xs text-fg-muted">The Mac is offline: it needs to be online for someone to allow the request.</p> : null}
      </form>
    </Card>
  );
}

function Viewer({ session }: { session: Session }) {
  const screen = useRef<HTMLDivElement>(null);
  const rfb = useRef<RFBType | null>(null);
  const [state, setState] = useState<"connecting" | "credentials" | "connected" | "disconnected">("connecting");
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [viewOnly, setViewOnly] = useState(false);
  const [creds, setCreds] = useState({ username: "", password: "" });

  useEffect(() => {
    let cancelled = false;
    setState("connecting");
    setError(null);
    (async () => {
      try {
        const [{ default: RFB }, t] = await Promise.all([import("@novnc/novnc"), unwrap(api.POST("/v1/remote-assist/sessions/{id}/ticket", { params: { path: { id: session.id } } }))]);
        if (cancelled || !screen.current) return;
        const r = new RFB(screen.current, t.ws_url, { wsProtocols: ["binary", `nexus-ticket.${t.ticket}`], shared: true });
        r.scaleViewport = true;
        r.background = "transparent";
        r.addEventListener("connect", () => (setState("connected"), r.focus()));
        r.addEventListener("credentialsrequired", () => setState("credentials"));
        r.addEventListener("securityfailure", (e) => setError((e as CustomEvent<{ reason?: string }>).detail.reason || "The Mac refused those credentials"));
        r.addEventListener("disconnect", (e) => {
          setState("disconnected");
          if (!(e as CustomEvent<{ clean: boolean }>).detail.clean) setError((prev) => prev ?? "The connection dropped");
        });
        rfb.current = r;
      } catch (err) {
        if (!cancelled) (setError(err instanceof Error ? err.message : "Couldn't connect"), setState("disconnected"));
      }
    })();
    return () => {
      cancelled = true;
      rfb.current?.disconnect();
      rfb.current = null;
    };
  }, [session.id, attempt]);

  useEffect(() => {
    if (rfb.current) rfb.current.viewOnly = viewOnly;
  }, [viewOnly, state]);

  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2 text-[13px]">
        <StatusPill tone={state === "connected" ? "success" : state === "disconnected" ? "neutral" : "warning"}>
          {state === "connected" ? "Connected" : state === "credentials" ? "Sign in to the Mac" : state === "disconnected" ? "Disconnected" : "Connecting…"}
        </StatusPill>
        <span className="text-fg-muted">{session.detail}. Ends on its own {timeAgo(session.expires_at)}.</span>
        <div className="ml-auto flex gap-1.5">
          <Button size="sm" variant="ghost" onClick={() => setViewOnly(!viewOnly)} title={viewOnly ? "Take control" : "Stop controlling (view only)"}>
            {viewOnly ? <Eye /> : <Hand />} {viewOnly ? "View only" : "Controlling"}
          </Button>
          <Button size="sm" variant="ghost" aria-label="Full screen" onClick={() => screen.current?.requestFullscreen()}>
            <Maximize2 />
          </Button>
          {state === "disconnected" ? (
            <Button size="sm" onClick={() => setAttempt((a) => a + 1)}>
              <RefreshCw /> Reconnect
            </Button>
          ) : null}
        </div>
      </div>
      {error ? (
        <div className="p-3">
          <ErrorBanner error={new Error(error)} />
        </div>
      ) : null}
      {state === "credentials" ? (
        <form
          className="flex flex-wrap items-end gap-2 border-b border-border p-3"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            rfb.current?.sendCredentials(creds);
            setCreds({ username: creds.username, password: "" });
          }}
        >
          <Field label="Mac account" htmlFor="ra-user">
            <Input id="ra-user" autoComplete="off" value={creds.username} onChange={(e) => setCreds({ ...creds, username: e.target.value })} />
          </Field>
          <Field label="Password" htmlFor="ra-pw">
            <Input id="ra-pw" type="password" autoComplete="off" value={creds.password} onChange={(e) => setCreds({ ...creds, password: e.target.value })} />
          </Field>
          <Button type="submit" variant="primary" disabled={!creds.username || !creds.password}>
            Sign in
          </Button>
          <p className="w-full text-xs text-fg-muted">macOS Screen Sharing asks for an account on this Mac, such as its local admin account. Nexus only relays it, encrypted for the Mac.</p>
        </form>
      ) : null}
      <div ref={screen} className="h-[70vh] w-full bg-black" />
    </Card>
  );
}
