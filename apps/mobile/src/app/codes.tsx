import { CameraView, useCameraPermissions } from "expo-camera";
import * as Clipboard from "expo-clipboard";
import { randomUUID } from "expo-crypto";
import { useFocusEffect } from "expo-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, FlatList, KeyboardAvoidingView, Platform, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { Button, Card, ErrorText } from "@/components/ui";
import { deleteOtpAccount, loadOtpAccounts, saveOtpAccount } from "@/lib/store";
import { useTheme } from "@/lib/theme";
import { base32Decode, formatCode, parseOtpauth, totp, type OtpAccount } from "@/lib/totp";

/**
 * Authenticator codes, made on this phone: they work with no connection, for Nexus (My security →
 * Add method → Authenticator app) and any other service that shows an authenticator QR code.
 */
export default function Codes() {
  const t = useTheme();
  const [accounts, setAccounts] = useState<OtpAccount[] | null>(null);
  const [adding, setAdding] = useState<null | "scan" | "key">(null);
  const [now, setNow] = useState(Date.now());
  const [copied, setCopied] = useState<string | null>(null);

  const reload = useCallback(() => void loadOtpAccounts().then(setAccounts), []);
  useFocusEffect(reload);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  if (adding) return <AddAccount mode={adding} onMode={setAdding} onDone={() => (setAdding(null), reload())} />;

  return (
    <FlatList
      contentContainerStyle={styles.container}
      data={accounts ?? []}
      keyExtractor={(a) => a.id}
      ListHeaderComponent={
        <View style={{ gap: 12 }}>
          <Text style={{ color: t.fgMuted, fontSize: 14, lineHeight: 20 }}>
            Codes are made on this phone, so they work without a connection. Tap one to copy it; press and hold to remove it.
          </Text>
          <View style={{ flexDirection: "row", gap: 10 }}>
            <View style={{ flex: 1 }}>
              <Button title="Scan a QR code" onPress={() => setAdding("scan")} />
            </View>
            <View style={{ flex: 1 }}>
              <Button title="Enter a key" variant="secondary" onPress={() => setAdding("key")} />
            </View>
          </View>
        </View>
      }
      ListEmptyComponent={
        accounts ? (
          <Card style={{ gap: 6 }}>
            <Text style={{ color: t.fg, fontWeight: "600", fontSize: 15 }}>No codes yet</Text>
            <Text style={{ color: t.fgMuted, lineHeight: 20 }}>
              For Nexus: in the console, go to My security → Add method → Authenticator app, and scan its QR code here.
            </Text>
          </Card>
        ) : null
      }
      renderItem={({ item }) => {
        const { code, remaining } = totp(item, now);
        const soon = remaining <= 5;
        return (
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={`${item.issuer || item.label} code ${code.split("").join(" ")}, ${remaining} seconds left. Tap to copy.`}
            onPress={async () => {
              await Clipboard.setStringAsync(code);
              setCopied(item.id);
              setTimeout(() => setCopied((c) => (c === item.id ? null : c)), 1500);
            }}
            onLongPress={() =>
              Alert.alert(`Remove ${item.issuer || item.label}?`, "Make sure you can still sign in to it another way first.", [
                { text: "Cancel", style: "cancel" },
                { text: "Remove", style: "destructive", onPress: () => void deleteOtpAccount(item.id).then(reload) },
              ])
            }
          >
            <Card style={{ gap: 4 }}>
              <Text style={{ color: t.fgMuted, fontSize: 13 }} numberOfLines={1}>
                {item.issuer ? `${item.issuer} · ${item.label}` : item.label}
              </Text>
              <View style={{ flexDirection: "row", alignItems: "center", justifyContent: "space-between" }}>
                <Text style={[styles.code, { color: soon ? t.warning : t.fg }]}>{formatCode(code)}</Text>
                <Text style={{ color: copied === item.id ? t.success : t.fgSubtle, fontVariant: ["tabular-nums"] }}>{copied === item.id ? "Copied" : `${remaining}s`}</Text>
              </View>
              <View style={[styles.track, { backgroundColor: t.bgMuted }]}>
                <View style={[styles.bar, { width: `${(remaining / item.period) * 100}%`, backgroundColor: soon ? t.warning : t.primary }]} />
              </View>
            </Card>
          </Pressable>
        );
      }}
      ItemSeparatorComponent={() => <View style={{ height: 10 }} />}
    />
  );
}

function AddAccount({ mode, onMode, onDone }: { mode: "scan" | "key"; onMode: (m: "scan" | "key" | null) => void; onDone: () => void }) {
  const t = useTheme();
  const [permission, requestPermission] = useCameraPermissions();
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [secret, setSecret] = useState("");
  const handled = useRef(false);

  const save = async (a: Omit<OtpAccount, "id">) => {
    await saveOtpAccount({ id: randomUUID(), ...a });
    onDone();
  };

  return (
    <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : undefined} style={{ flex: 1 }}>
      <ScrollView contentContainerStyle={styles.container}>
        <ErrorText>{error}</ErrorText>
        {mode === "scan" ? (
          permission?.granted ? (
            <View style={[styles.camera, { borderColor: t.border }]}>
              <CameraView
                style={StyleSheet.absoluteFill}
                barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
                onBarcodeScanned={({ data }) => {
                  if (handled.current) return;
                  try {
                    const parsed = parseOtpauth(data);
                    handled.current = true;
                    void save(parsed);
                  } catch (e) {
                    setError(e instanceof Error ? e.message : "That QR code can't be used");
                  }
                }}
              />
            </View>
          ) : (
            <Card style={{ gap: 12 }}>
              <Text style={{ color: t.fg }}>Nexus needs your camera to scan the QR code.</Text>
              <Button title="Allow camera" onPress={requestPermission} />
            </Card>
          )
        ) : (
          <Card style={{ gap: 12 }}>
            <Text style={[styles.label, { color: t.fg }]}>Account name</Text>
            <TextInput value={name} onChangeText={setName} placeholder="Nexus (ana@acme.com)" placeholderTextColor={t.fgSubtle} style={[styles.input, { borderColor: t.border, color: t.fg }]} />
            <Text style={[styles.label, { color: t.fg }]}>Key</Text>
            <TextInput
              value={secret}
              onChangeText={setSecret}
              placeholder="JBSW Y3DP EHPK 3PXP"
              placeholderTextColor={t.fgSubtle}
              autoCapitalize="characters"
              autoCorrect={false}
              style={[styles.input, { borderColor: t.border, color: t.fg, fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace" }]}
            />
            <Button
              title="Add"
              disabled={!name.trim() || !secret.trim()}
              onPress={() => {
                try {
                  const key = secret.toUpperCase().replace(/[\s-]/g, "");
                  base32Decode(key);
                  void save({ issuer: "", label: name.trim(), secret: key, algorithm: "SHA1", digits: 6, period: 30 });
                } catch (e) {
                  setError(e instanceof Error ? e.message : "That key can't be used");
                }
              }}
            />
          </Card>
        )}
        <Button title={mode === "scan" ? "Enter a key instead" : "Scan a QR code instead"} variant="ghost" onPress={() => (setError(null), onMode(mode === "scan" ? "key" : "scan"))} />
        <Button title="Cancel" variant="ghost" onPress={() => onMode(null)} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, gap: 16 },
  code: { fontSize: 32, fontWeight: "700", letterSpacing: 2, fontVariant: ["tabular-nums"] },
  track: { height: 3, borderRadius: 2, overflow: "hidden", marginTop: 6 },
  bar: { height: 3 },
  camera: { height: 320, borderRadius: 16, overflow: "hidden", borderWidth: 1 },
  label: { fontSize: 14, fontWeight: "600" },
  input: { height: 48, borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, fontSize: 15 },
});
