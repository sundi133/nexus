import type { Schemas } from "@nexus/api-client";
import * as LocalAuthentication from "expo-local-authentication";
import { router, useLocalSearchParams } from "expo-router";
import { useEffect, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { Button, Card, ErrorText } from "@/components/ui";
import { errorMessage, unwrap } from "@/lib/api";
import { signDecision } from "@/lib/keys";
import { useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";

type Challenge = Schemas["PendingPushChallenge"];

function describeClient(ua: string) {
  const browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "A browser";
  const os = /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

/** Biometric (or device passcode) gate before the private key is used. */
async function confirmWithBiometrics(prompt: string) {
  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  const enrolled = hasHardware && (await LocalAuthentication.isEnrolledAsync());
  if (!enrolled) return true; // no biometrics set up: the device unlock already protects the keystore
  const r = await LocalAuthentication.authenticateAsync({ promptMessage: prompt, cancelLabel: "Cancel" });
  return r.success;
}

export default function Approve() {
  const t = useTheme();
  const session = useSession();
  const { id } = useLocalSearchParams<{ id: string }>();
  const [challenge, setChallenge] = useState<Challenge | null | undefined>(undefined);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<null | "approved" | "denied" | "blocked">(null);

  useEffect(() => {
    if (session.status !== "paired") return;
    unwrap(session.api.GET("/v1/me/mfa-challenges"))
      .then((r) => setChallenge(r.data.find((c) => c.id === id) ?? null))
      .catch((err) => setError(errorMessage(err)));
  }, [session, id]);

  if (session.status !== "paired") return null;
  const { api, pairing } = session;

  const respond = async (decision: "approve" | "deny", opts: { choice?: number; reason?: "not_me" | "mistake" }) => {
    setBusy(decision === "approve" ? String(opts.choice) : (opts.reason ?? "deny"));
    setError(null);
    try {
      if (decision === "approve" && !(await confirmWithBiometrics("Approve sign-in"))) return;
      const signature = signDecision(pairing.secretKey, id, decision, decision === "approve" ? (opts.choice ?? null) : null);
      const r = await unwrap(
        api.POST("/v1/me/mfa-challenges/{id}/respond", {
          params: { path: { id } },
          body: { decision, choice: opts.choice, reason: opts.reason, factor_id: pairing.factorId, signature },
        }),
      );
      setResult(r.status === "approved" ? "approved" : r.reason === "mistake" ? "denied" : "blocked");
      setTimeout(() => (router.canGoBack() ? router.back() : router.replace("/")), 1600);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  if (result) {
    const copy = {
      approved: { title: "Approved", body: "You're signed in.", color: t.success },
      denied: { title: "Declined", body: "The sign-in was not allowed.", color: t.fgMuted },
      blocked: { title: "Blocked", body: "We stopped that sign-in and alerted your security team. Change your password soon.", color: t.danger },
    }[result];
    return (
      <View style={[styles.center, { backgroundColor: t.bg }]}>
        <Text style={[styles.result, { color: copy.color }]}>{copy.title}</Text>
        <Text style={{ color: t.fgMuted, textAlign: "center", fontSize: 16, paddingHorizontal: 32 }}>{copy.body}</Text>
      </View>
    );
  }

  if (challenge === undefined) return <View style={[styles.center, { backgroundColor: t.bg }]} />;
  if (challenge === null) {
    return (
      <View style={[styles.center, { backgroundColor: t.bg, gap: 16 }]}>
        <Text style={{ color: t.fg, fontSize: 18, fontWeight: "600" }}>This request has expired</Text>
        <Button title="Close" variant="secondary" onPress={() => router.replace("/")} />
      </View>
    );
  }

  const ctx = challenge.context;
  return (
    <ScrollView style={{ backgroundColor: t.bg }} contentContainerStyle={styles.container}>
      <Text style={[styles.title, { color: t.fg }]}>Are you signing in?</Text>
      <Card style={{ gap: 6 }}>
        <Text style={{ color: t.fg, fontSize: 16, fontWeight: "600" }}>{pairing.orgName}</Text>
        <Text style={{ color: t.fgMuted }}>{describeClient(ctx.user_agent)}</Text>
        <Text style={{ color: t.fgMuted }}>IP address {ctx.ip || "unknown"}</Text>
        <Text style={{ color: t.fgMuted }}>{new Date(ctx.requested_at).toLocaleTimeString()}</Text>
      </Card>

      <Text style={[styles.instruction, { color: t.fg }]}>Tap the number shown on your screen</Text>
      <View style={styles.numbers}>
        {challenge.choices.map((n) => (
          <Pressable
            key={n}
            accessibilityRole="button"
            accessibilityLabel={`Number ${n}`}
            disabled={!!busy}
            onPress={() => respond("approve", { choice: n })}
            style={({ pressed }) => [styles.number, { borderColor: t.primary, backgroundColor: pressed || busy === String(n) ? t.primarySoft : t.bg }]}
          >
            <Text style={[styles.numberText, { color: t.primary }]}>{n}</Text>
          </Pressable>
        ))}
      </View>

      <ErrorText>{error}</ErrorText>

      <View style={{ gap: 10, marginTop: 8 }}>
        <Button title="This wasn't me" variant="danger" loading={busy === "not_me"} onPress={() => respond("deny", { reason: "not_me" })} />
        <Button title="Deny" variant="secondary" loading={busy === "mistake"} onPress={() => respond("deny", { reason: "mistake" })} />
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, gap: 18, paddingBottom: 48 },
  center: { flex: 1, alignItems: "center", justifyContent: "center", gap: 8 },
  title: { fontSize: 28, fontWeight: "700" },
  instruction: { fontSize: 16, fontWeight: "600", textAlign: "center", marginTop: 8 },
  numbers: { flexDirection: "row", justifyContent: "space-between", gap: 12 },
  number: { flex: 1, height: 88, borderRadius: 16, borderWidth: 2, alignItems: "center", justifyContent: "center" },
  numberText: { fontSize: 36, fontWeight: "700", fontVariant: ["tabular-nums"] },
  result: { fontSize: 34, fontWeight: "800" },
});
