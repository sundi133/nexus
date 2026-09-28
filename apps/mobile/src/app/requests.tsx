import type { Schemas } from "@nexus/api-client";
import { router, useFocusEffect } from "expo-router";
import { useCallback, useState } from "react";
import { Alert, RefreshControl, SectionList, StyleSheet, Text, View } from "react-native";
import { Button, Card, ErrorText } from "@/components/ui";
import { errorMessage, unwrap } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";

type Request = Schemas["AccessRequest"];

const KIND: Record<Request["resource"]["type"], string> = { app: "App", group: "Group", role: "Admin role", block_exception: "Blocked app", software: "Software" };

function timeLeft(iso: string) {
  const ms = new Date(iso).getTime() - Date.now();
  if (ms <= 0) return "ending now";
  const h = Math.floor(ms / 3_600_000);
  const m = Math.round((ms % 3_600_000) / 60_000);
  return h >= 48 ? `${Math.round(h / 24)} days left` : h ? `${h} h ${m} min left` : `${m} min left`;
}
const at = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

/** What you've asked for: waiting, granted (and until when), and how the rest turned out. */
export default function MyRequests() {
  const t = useTheme();
  const session = useSession();
  const [requests, setRequests] = useState<Request[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    if (session.status !== "paired") return;
    try {
      setRequests((await unwrap(session.api.GET("/v1/access/requests", { params: { query: { view: "mine", limit: 50 } } }))).data);
      setError(null);
    } catch (err) {
      if (!session.onUnauthorized(err)) setError(errorMessage(err));
    }
  }, [session]);

  // Decisions show up within seconds while the screen is open.
  useFocusEffect(
    useCallback(() => {
      void load();
      const timer = setInterval(load, 5000);
      return () => clearInterval(timer);
    }, [load]),
  );

  if (session.status !== "paired") return null;
  const api = session.api;

  const act = (r: Request, action: "cancel" | "revoke") => {
    const title = action === "cancel" ? `Withdraw your request for ${r.resource.name}?` : `Give back ${r.resource.name}?`;
    const body = action === "cancel" ? "Approvers won't be asked any more." : r.resource.type === "block_exception" ? "It's blocked again on your computers within a minute." : "Your access ends now.";
    Alert.alert(title, body, [
      { text: "Keep it", style: "cancel" },
      {
        text: action === "cancel" ? "Withdraw" : "Give back",
        style: "destructive",
        onPress: async () => {
          setBusy(r.id);
          try {
            if (action === "cancel") await unwrap(api.POST("/v1/access/requests/{id}/cancel", { params: { path: { id: r.id } } }));
            else await unwrap(api.POST("/v1/access/requests/{id}/revoke", { params: { path: { id: r.id } }, body: { reason: "Given back from Nexus Mobile" } }));
            await load();
          } catch (err) {
            setError(errorMessage(err));
          } finally {
            setBusy(null);
          }
        },
      },
    ]);
  };

  const all = requests ?? [];
  const sections = [
    { title: "ACTIVE", data: all.filter((r) => r.status === "active") },
    { title: "WAITING FOR APPROVAL", data: all.filter((r) => r.status === "pending") },
    { title: "EARLIER", data: all.filter((r) => r.status !== "active" && r.status !== "pending").slice(0, 20) },
  ].filter((s) => s.data.length);

  return (
    <SectionList
      contentContainerStyle={styles.container}
      sections={sections}
      keyExtractor={(r) => r.id}
      stickySectionHeadersEnabled={false}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={async () => (setRefreshing(true), await load(), setRefreshing(false))} />}
      ListHeaderComponent={
        <View style={{ gap: 12, marginBottom: 4 }}>
          <Button title="Ask for access" onPress={() => router.push("/catalog")} />
          <ErrorText>{error}</ErrorText>
        </View>
      }
      ListEmptyComponent={
        requests ? (
          <Card>
            <Text style={{ color: t.fgMuted, lineHeight: 20 }}>No requests yet. Ask for an app, software, or a blocked app you need for work.</Text>
          </Card>
        ) : null
      }
      renderSectionHeader={({ section }) => <Text style={[styles.section, { color: t.fgMuted }]}>{section.title}</Text>}
      renderItem={({ item: r }) => {
        const lastDecision = r.decisions.at(-1);
        const tone = r.status === "active" ? t.success : r.status === "pending" ? t.warning : r.status === "denied" ? t.danger : t.fgSubtle;
        const label = { active: "Granted", pending: "Waiting", denied: "Denied", canceled: "Withdrawn", ended: "Ended", revoked: "Ended early" }[r.status];
        return (
          <Card style={{ gap: 6, marginBottom: 10 }}>
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
              <Text style={{ color: t.fg, fontSize: 16, fontWeight: "600", flex: 1 }} numberOfLines={1}>
                {r.resource.name}
              </Text>
              <Text style={{ color: tone, fontWeight: "600", fontSize: 13 }}>{label}</Text>
            </View>
            <Text style={{ color: t.fgMuted, fontSize: 13 }}>
              {KIND[r.resource.type]} · asked {at(r.created_at)}
            </Text>
            {r.status === "active" ? (
              <Text style={{ color: t.fg }}>{r.expires_at ? `Until ${at(r.expires_at)} (${timeLeft(r.expires_at)})` : "No end date"}</Text>
            ) : r.status === "pending" ? (
              <Text style={{ color: t.fg }}>
                {r.stages > 1 ? `Step ${r.stage + 1} of ${r.stages}: ` : ""}waiting for {r.approvers.length ? r.approvers.join(", ") : "an approver"}
              </Text>
            ) : null}
            {r.status === "denied" && lastDecision ? (
              <Text style={{ color: t.fg }}>
                {lastDecision.approver} denied it{lastDecision.comment ? `: “${lastDecision.comment}”` : "."}
              </Text>
            ) : null}
            {(r.status === "ended" || r.status === "revoked") && r.end_reason ? <Text style={{ color: t.fgMuted }}>{r.end_reason}</Text> : null}
            {r.status === "active" ? <Button title="Give back" variant="secondary" loading={busy === r.id} onPress={() => act(r, "revoke")} /> : null}
            {r.status === "pending" ? <Button title="Withdraw" variant="secondary" loading={busy === r.id} onPress={() => act(r, "cancel")} /> : null}
          </Card>
        );
      }}
    />
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, gap: 4 },
  section: { fontSize: 12, fontWeight: "600", letterSpacing: 0.6, marginTop: 12, marginBottom: 8 },
});
