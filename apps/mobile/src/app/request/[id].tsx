import type { Schemas } from "@nexus/api-client";
import { router, useLocalSearchParams } from "expo-router";
import { useEffect, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { Button, Card, ErrorText } from "@/components/ui";
import { errorMessage, unwrap } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";

type Item = Schemas["AccessCatalogItem"];
const HOURS = [1, 4, 8, 24, 72, 168];
const label = (h: number | null) => (h == null ? "Permanently" : h < 24 ? `${h} h` : `${h / 24} d`);

/** Ask for something in the access catalog, e.g. a blocked app from its "stopped" notification. */
export default function RequestAccess() {
  const t = useTheme();
  const session = useSession();
  const { id } = useLocalSearchParams<{ id: string }>();
  const [item, setItem] = useState<Item | null | undefined>(undefined);
  const [why, setWhy] = useState("");
  const [hours, setHours] = useState<number | null>(8);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  useEffect(() => {
    if (session.status !== "paired") return;
    unwrap(session.api.GET("/v1/access/catalog"))
      .then((r) => {
        const found = r.data.find((c) => c.id === id) ?? null;
        setItem(found);
        if (found) setHours(HOURS.filter((h) => h <= found.max_hours).at(-1) ?? found.max_hours);
      })
      .catch((err) => setError(errorMessage(err)));
  }, [session, id]);

  if (session.status !== "paired") return null;
  if (item === undefined) return <ErrorText>{error}</ErrorText>;
  if (item === null) return <Text style={{ color: t.fgMuted, padding: 24 }}>This can't be requested any more. Ask IT if you need it.</Text>;

  const options: (number | null)[] = [...HOURS.filter((h) => h <= item.max_hours), ...(item.allow_permanent ? [null] : [])];
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await unwrap(session.api.POST("/v1/access/requests", { body: { catalog_id: item.id, justification: why.trim(), duration_hours: hours } }));
      setSent(true);
      setTimeout(() => (router.canGoBack() ? router.back() : router.replace("/")), 1600);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (sent)
    return (
      <View style={[styles.center, { backgroundColor: t.bg }]}>
        <Text style={{ color: t.success, fontSize: 28, fontWeight: "700" }}>Requested</Text>
        <Text style={{ color: t.fgMuted, textAlign: "center", paddingHorizontal: 32 }}>You'll get a notification when it's decided.</Text>
      </View>
    );

  return (
    <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }}>
      <Card style={{ gap: 4 }}>
        <Text style={{ color: t.fg, fontSize: 20, fontWeight: "700" }}>{item.name}</Text>
        {item.description ? <Text style={{ color: t.fgMuted }}>{item.description}</Text> : null}
        {item.you.has_access ? <Text style={{ color: t.success, marginTop: 6 }}>You already have it.</Text> : null}
        {item.you.open_request ? <Text style={{ color: t.warning, marginTop: 6 }}>You've already asked: it's waiting for approval.</Text> : null}
      </Card>
      {!item.you.has_access && !item.you.open_request ? (
        <>
          <Text style={[styles.label, { color: t.fgMuted }]}>WHY DO YOU NEED IT?</Text>
          <TextInput
            value={why}
            onChangeText={setWhy}
            multiline
            placeholder="e.g. Needed for the customer demo on Friday"
            placeholderTextColor={t.fgSubtle}
            style={[styles.input, { color: t.fg, borderColor: t.border, backgroundColor: t.bg }]}
            maxLength={500}
          />
          <Text style={[styles.label, { color: t.fgMuted }]}>FOR HOW LONG?</Text>
          <View style={styles.chips}>
            {options.map((h) => (
              <Pressable key={String(h)} accessibilityRole="button" accessibilityState={{ selected: hours === h }} onPress={() => setHours(h)} style={[styles.chip, { borderColor: hours === h ? t.primary : t.border, backgroundColor: hours === h ? t.primarySoft : t.bg }]}>
                <Text style={{ color: hours === h ? t.primary : t.fg, fontWeight: "600" }}>{label(h)}</Text>
              </Pressable>
            ))}
          </View>
          <ErrorText>{error}</ErrorText>
          <Button title="Send request" loading={busy} disabled={why.trim().length < 5} onPress={() => void submit()} />
        </>
      ) : null}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  center: { flex: 1, alignItems: "center", justifyContent: "center", gap: 8 },
  label: { fontSize: 12, fontWeight: "600", letterSpacing: 0.6, marginTop: 4 },
  input: { borderWidth: 1, borderRadius: 12, padding: 12, minHeight: 90, textAlignVertical: "top", fontSize: 16 },
  chips: { flexDirection: "row", flexWrap: "wrap", gap: 8 },
  chip: { borderWidth: 1, borderRadius: 999, paddingHorizontal: 14, paddingVertical: 8 },
});
