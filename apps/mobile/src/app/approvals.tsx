import type { Schemas } from "@nexus/api-client";
import { useFocusEffect } from "expo-router";
import { useCallback, useState } from "react";
import { Alert, FlatList, RefreshControl, StyleSheet, Text, View } from "react-native";
import { Button, Card, ErrorText } from "@/components/ui";
import { errorMessage, unwrap } from "@/lib/api";
import { confirmWithBiometrics } from "@/lib/biometrics";
import { useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";

type Req = Schemas["AccessRequest"];

const KIND: Record<string, string> = { app: "App", group: "Group", role: "Admin role", block_exception: "Blocked app", software: "Software" };
const duration = (h: number | null | undefined) => (h == null ? "permanently" : h < 24 ? `for ${h} h` : `for ${Math.round(h / 24)} days`);

/** Requests waiting for this person's approval: apps, groups, roles, blocked apps and software. */
export default function Approvals() {
  const t = useTheme();
  const session = useSession();
  const [items, setItems] = useState<Req[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    if (session.status !== "paired") return;
    try {
      setItems((await unwrap(session.api.GET("/v1/access/requests", { params: { query: { view: "approvals" } } }))).data);
      setError(null);
    } catch (err) {
      if (!session.onUnauthorized(err)) setError(errorMessage(err));
    }
  }, [session]);

  useFocusEffect(
    useCallback(() => {
      void load();
      const timer = setInterval(load, 10_000);
      return () => clearInterval(timer);
    }, [load]),
  );

  if (session.status !== "paired") return null;
  const { api } = session;

  const decide = async (r: Req, decision: "approve" | "deny") => {
    setBusy(`${r.id}:${decision}`);
    setError(null);
    try {
      if (decision === "approve" && !(await confirmWithBiometrics(`Approve ${r.resource.name}`))) return;
      await unwrap(api.POST("/v1/access/requests/{id}/decision", { params: { path: { id: r.id } }, body: { decision, comment: "" } }));
      await load();
    } catch (err) {
      const msg = errorMessage(err);
      // Admin roles need a fresh MFA in the console.
      setError(/step.?up|recent/i.test(msg) ? "Approve admin role requests in the Nexus console: they need a fresh MFA check there." : msg);
    } finally {
      setBusy(null);
    }
  };

  return (
    <FlatList
      contentContainerStyle={styles.container}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={async () => (setRefreshing(true), await load(), setRefreshing(false))} />}
      ListHeaderComponent={<ErrorText>{error}</ErrorText>}
      data={items ?? []}
      keyExtractor={(r) => r.id}
      renderItem={({ item: r }) => (
        <Card style={{ gap: 6 }}>
          <Text style={[styles.kind, { color: t.fgMuted }]}>{KIND[r.resource.type] ?? r.resource.type}</Text>
          <Text style={[styles.title, { color: t.fg }]}>{r.resource.name}</Text>
          <Text style={{ color: t.fg }}>
            {r.requester.email} · {duration(r.duration_hours)}
          </Text>
          <Text style={{ color: t.fgMuted }}>“{r.justification}”</Text>
          {r.stages > 1 ? <Text style={{ color: t.fgSubtle, fontSize: 12 }}>Approval {r.stage + 1} of {r.stages}</Text> : null}
          <View style={styles.actions}>
            <View style={{ flex: 1 }}>
              <Button
                title="Deny"
                variant="secondary"
                loading={busy === `${r.id}:deny`}
                onPress={() => Alert.alert(`Deny ${r.requester.email}?`, r.resource.name, [{ text: "Cancel", style: "cancel" }, { text: "Deny", style: "destructive", onPress: () => void decide(r, "deny") }])}
              />
            </View>
            <View style={{ flex: 1 }}>
              <Button title="Approve" loading={busy === `${r.id}:approve`} onPress={() => void decide(r, "approve")} />
            </View>
          </View>
        </Card>
      )}
      ListEmptyComponent={items ? <Text style={{ color: t.fgMuted, textAlign: "center", padding: 24 }}>Nothing waiting for you.</Text> : null}
    />
  );
}

const styles = StyleSheet.create({
  container: { padding: 16, gap: 12 },
  kind: { fontSize: 12, fontWeight: "600", letterSpacing: 0.5, textTransform: "uppercase" },
  title: { fontSize: 18, fontWeight: "700" },
  actions: { flexDirection: "row", gap: 10, marginTop: 8 },
});
