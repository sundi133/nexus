import type { Schemas } from "@nexus/api-client";
import { Redirect, router, useFocusEffect } from "expo-router";
import { useCallback, useState } from "react";
import { Alert, FlatList, Pressable, RefreshControl, StyleSheet, Text, View } from "react-native";
import { Button, Card } from "@/components/ui";
import { errorMessage, unwrap } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";

type Challenge = Schemas["PendingPushChallenge"];
type Notification = Schemas["Notification"];

export default function Home() {
  const session = useSession();
  const t = useTheme();
  const [challenges, setChallenges] = useState<Challenge[]>([]);
  const [inbox, setInbox] = useState<Notification[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (session.status !== "paired") return;
    try {
      const [c, n] = await Promise.all([
        unwrap(session.api.GET("/v1/me/mfa-challenges")),
        unwrap(session.api.GET("/v1/me/notifications", { params: { query: { limit: 20, filter: "all" } } })),
      ]);
      setChallenges(c.data);
      setInbox(n.data);
      setError(null);
    } catch (err) {
      if (!session.onUnauthorized(err)) setError(errorMessage(err));
    }
  }, [session]);

  // Poll while the screen is visible: approvals must appear within seconds even when pushes aren't available.
  useFocusEffect(
    useCallback(() => {
      void load();
      const timer = setInterval(load, 3000);
      return () => clearInterval(timer);
    }, [load]),
  );

  if (session.status === "loading") return null;
  if (session.status === "unpaired") return <Redirect href="/pair" />;

  const { pairing } = session;
  return (
    <FlatList
      contentContainerStyle={styles.container}
      refreshControl={
        <RefreshControl
          refreshing={refreshing}
          onRefresh={async () => {
            setRefreshing(true);
            await load();
            setRefreshing(false);
          }}
        />
      }
      ListHeaderComponent={
        <View style={{ gap: 16 }}>
          <Card>
            <Text style={[styles.caption, { color: t.fgMuted }]}>{pairing.orgName}</Text>
            <Text style={[styles.title, { color: t.fg }]}>{pairing.user.displayName}</Text>
            <Text style={{ color: t.fgMuted }}>{pairing.user.email}</Text>
            <View style={[styles.badge, { backgroundColor: t.primarySoft }]}>
              <Text style={{ color: t.primary, fontWeight: "600", fontSize: 12 }}>● This phone approves your sign-ins</Text>
            </View>
          </Card>

          {challenges.map((c) => (
            <Pressable
              key={c.id}
              accessibilityRole="button"
              onPress={() => router.push({ pathname: "/approve/[id]", params: { id: c.id } })}
              style={[styles.pending, { backgroundColor: t.primary }]}
            >
              <Text style={styles.pendingTitle}>Sign-in request waiting</Text>
              <Text style={styles.pendingBody}>Tap to review and approve</Text>
            </Pressable>
          ))}

          {error ? <Text style={{ color: t.danger }}>{error}</Text> : null}
          <Text style={[styles.section, { color: t.fgMuted }]}>NOTIFICATIONS</Text>
        </View>
      }
      data={inbox}
      keyExtractor={(n) => n.id}
      renderItem={({ item }) => (
        <View style={[styles.row, { borderColor: t.border, backgroundColor: t.bg }]}>
          <View style={[styles.dot, { backgroundColor: item.read ? "transparent" : item.severity === "critical" ? t.danger : item.severity === "warning" ? t.warning : t.primary }]} />
          <View style={{ flex: 1 }}>
            <Text style={{ color: t.fg, fontWeight: item.read ? "400" : "600" }}>{item.title}</Text>
            {item.body ? <Text style={{ color: t.fgMuted, marginTop: 2 }}>{item.body}</Text> : null}
            <Text style={{ color: t.fgSubtle, marginTop: 4, fontSize: 12 }}>{new Date(item.created_at).toLocaleString()}</Text>
          </View>
        </View>
      )}
      ListEmptyComponent={<Text style={{ color: t.fgMuted, textAlign: "center", padding: 24 }}>You're all caught up.</Text>}
      ListFooterComponent={
        <View style={{ marginTop: 24 }}>
          <Button
            title="Unpair this phone"
            variant="ghost"
            onPress={() =>
              Alert.alert("Unpair this phone?", "You'll need another way to verify sign-ins, such as a passkey or authenticator app.", [
                { text: "Cancel", style: "cancel" },
                { text: "Unpair", style: "destructive", onPress: () => void session.unpair() },
              ])
            }
          />
        </View>
      }
    />
  );
}

const styles = StyleSheet.create({
  container: { padding: 16, gap: 8 },
  caption: { fontSize: 13, fontWeight: "500" },
  title: { fontSize: 22, fontWeight: "700", marginTop: 2 },
  badge: { alignSelf: "flex-start", borderRadius: 999, paddingHorizontal: 10, paddingVertical: 4, marginTop: 12 },
  pending: { borderRadius: 14, padding: 18 },
  pendingTitle: { color: "#fff", fontSize: 17, fontWeight: "700" },
  pendingBody: { color: "#E0E7FF", marginTop: 2 },
  section: { fontSize: 12, fontWeight: "600", letterSpacing: 0.6, marginTop: 8 },
  row: { flexDirection: "row", gap: 10, padding: 14, borderWidth: 1, borderRadius: 12 },
  dot: { width: 8, height: 8, borderRadius: 4, marginTop: 6 },
});
