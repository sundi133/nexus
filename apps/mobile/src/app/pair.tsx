import { CameraView, useCameraPermissions } from "expo-camera";
import { router, useLocalSearchParams } from "expo-router";
import { useEffect, useRef, useState } from "react";
import { KeyboardAvoidingView, Platform, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { Button, Card, ErrorText } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";

/** Parses the console's QR: nexus://pair?code=nxp_…&api=https://… */
function parsePairingUrl(data: string) {
  try {
    const url = new URL(data);
    const code = url.searchParams.get("code");
    const api = url.searchParams.get("api");
    return code?.startsWith("nxp_") && api ? { code, api } : null;
  } catch {
    return null;
  }
}

export default function Pair() {
  const t = useTheme();
  const session = useSession();
  const params = useLocalSearchParams<{ code?: string; api?: string }>();
  const [permission, requestPermission] = useCameraPermissions();
  const [manual, setManual] = useState(false);
  const [apiUrl, setApiUrl] = useState(params.api ?? "");
  const [code, setCode] = useState(params.code ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const handled = useRef(false);

  const submit = async (api: string, c: string) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await session.pair(api.trim(), c.trim());
      router.replace("/");
    } catch (err) {
      setError(errorMessage(err));
      handled.current = false;
    } finally {
      setBusy(false);
    }
  };

  // Opened from a deep link (nexus://pair?...): pair straight away.
  useEffect(() => {
    if (params.code && params.api && !handled.current) {
      handled.current = true;
      void submit(params.api, params.code);
    }
  }, [params.code, params.api]);

  return (
    <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : undefined} style={{ flex: 1 }}>
      <ScrollView contentContainerStyle={styles.container}>
        <Text style={[styles.title, { color: t.fg }]}>Approve sign-ins with a tap</Text>
        <Text style={{ color: t.fgMuted, fontSize: 15, lineHeight: 21 }}>
          In the Nexus console, go to My security → Add method → Nexus Mobile, then scan the QR code.
        </Text>

        <ErrorText>{error}</ErrorText>

        {!manual ? (
          permission?.granted ? (
            <View style={[styles.camera, { borderColor: t.border }]}>
              <CameraView
                style={StyleSheet.absoluteFill}
                barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
                onBarcodeScanned={({ data }) => {
                  if (handled.current || busy) return;
                  const parsed = parsePairingUrl(data);
                  if (!parsed) return setError("That isn't a Nexus pairing code.");
                  handled.current = true;
                  void submit(parsed.api, parsed.code);
                }}
              />
            </View>
          ) : (
            <Card style={{ gap: 12 }}>
              <Text style={{ color: t.fg }}>Nexus needs your camera to scan the pairing code.</Text>
              <Button title="Allow camera" onPress={requestPermission} />
            </Card>
          )
        ) : (
          <Card style={{ gap: 12 }}>
            <Text style={[styles.label, { color: t.fg }]}>Server address</Text>
            <TextInput
              value={apiUrl}
              onChangeText={setApiUrl}
              placeholder="https://api.nexus.votal.ai"
              placeholderTextColor={t.fgSubtle}
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
              style={[styles.input, { borderColor: t.border, color: t.fg }]}
            />
            <Text style={[styles.label, { color: t.fg }]}>Pairing code</Text>
            <TextInput
              value={code}
              onChangeText={setCode}
              placeholder="nxp_…"
              placeholderTextColor={t.fgSubtle}
              autoCapitalize="none"
              autoCorrect={false}
              style={[styles.input, { borderColor: t.border, color: t.fg }]}
            />
            <Button title="Pair this phone" loading={busy} disabled={!apiUrl || !code} onPress={() => submit(apiUrl, code)} />
          </Card>
        )}

        {busy ? <Text style={{ color: t.fgMuted, textAlign: "center" }}>Pairing…</Text> : null}
        <Button title={manual ? "Scan a QR code instead" : "Enter a code instead"} variant="ghost" onPress={() => setManual(!manual)} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, gap: 16 },
  title: { fontSize: 26, fontWeight: "700" },
  camera: { height: 320, borderRadius: 16, overflow: "hidden", borderWidth: 1 },
  label: { fontSize: 14, fontWeight: "600" },
  input: { height: 48, borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, fontSize: 15 },
});
