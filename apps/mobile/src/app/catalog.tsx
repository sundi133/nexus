import type { Schemas } from "@nexus/api-client";
import { router } from "expo-router";
import { useEffect, useState } from "react";
import { FlatList, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { Card, ErrorText } from "@/components/ui";
import { errorMessage, unwrap } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";

type Item = Schemas["AccessCatalogItem"];
const KIND: Record<Item["resource_type"], string> = { app: "App", group: "Group", role: "Admin role", block_exception: "Blocked app", software: "Software" };

/** What people can ask for. Admin roles need a fresh sign-in check, so they're asked for in the console. */
export default function Catalog() {
  const t = useTheme();
  const session = useSession();
  const [items, setItems] = useState<Item[] | null>(null);
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (session.status !== "paired") return;
    unwrap(session.api.GET("/v1/access/catalog"))
      .then((r) => setItems(r.data.filter((i) => i.enabled && i.resource_type !== "role")))
      .catch((err) => setError(errorMessage(err)));
  }, [session]);

  const shown = (items ?? []).filter((i) => `${i.name} ${i.description}`.toLowerCase().includes(q.trim().toLowerCase()));
  return (
    <FlatList
      contentContainerStyle={styles.container}
      data={shown}
      keyExtractor={(i) => i.id}
      ListHeaderComponent={
        <View style={{ gap: 12, marginBottom: 12 }}>
          <TextInput value={q} onChangeText={setQ} placeholder="Search" placeholderTextColor={t.fgSubtle} style={[styles.input, { borderColor: t.border, color: t.fg, backgroundColor: t.bg }]} />
          <ErrorText>{error}</ErrorText>
        </View>
      }
      ListEmptyComponent={items ? <Text style={{ color: t.fgMuted }}>{q ? "Nothing matches." : "There's nothing you can ask for yet. Your IT team adds things to the catalog."}</Text> : null}
      ItemSeparatorComponent={() => <View style={{ height: 10 }} />}
      renderItem={({ item }) => {
        const state = item.you.has_access ? "You have it" : item.you.open_request ? "Requested" : null;
        return (
          <Pressable
            accessibilityRole="button"
            disabled={!!state}
            onPress={() => router.push({ pathname: "/request/[id]", params: { id: item.id } })}
            style={({ pressed }) => ({ opacity: state ? 0.6 : pressed ? 0.85 : 1 })}
          >
            <Card style={{ gap: 4 }}>
              <View style={{ flexDirection: "row", justifyContent: "space-between", gap: 8 }}>
                <Text style={{ color: t.fg, fontSize: 16, fontWeight: "600", flex: 1 }}>{item.name}</Text>
                <Text style={{ color: state ? t.fgSubtle : t.primary, fontWeight: "600" }}>{state ?? "Ask →"}</Text>
              </View>
              <Text style={{ color: t.fgMuted, fontSize: 13 }}>
                {KIND[item.resource_type]} · up to {item.max_hours >= 24 ? `${Math.round(item.max_hours / 24)} days` : `${item.max_hours} h`}
                {item.allow_permanent ? " or permanently" : ""}
                {item.you.eligible ? " · pre-approved for you" : ""}
              </Text>
              {item.description ? <Text style={{ color: t.fg }}>{item.description}</Text> : null}
            </Card>
          </Pressable>
        );
      }}
    />
  );
}

const styles = StyleSheet.create({
  container: { padding: 20 },
  input: { height: 44, borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, fontSize: 15 },
});
