import { ActivityIndicator, Pressable, StyleSheet, Text, View, type PressableProps, type ViewProps } from "react-native";
import { useTheme } from "@/lib/theme";

export function Button({
  title,
  variant = "primary",
  loading,
  disabled,
  ...props
}: PressableProps & { title: string; variant?: "primary" | "secondary" | "danger" | "ghost"; loading?: boolean }) {
  const t = useTheme();
  const bg = { primary: t.primary, secondary: t.bg, danger: t.danger, ghost: "transparent" }[variant];
  const fg = { primary: t.primaryFg, secondary: t.fg, danger: "#fff", ghost: t.fgMuted }[variant];
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: !!(disabled || loading), busy: !!loading }}
      disabled={disabled || loading}
      style={({ pressed }) => [
        styles.button,
        { backgroundColor: bg, borderColor: variant === "secondary" ? t.border : bg, opacity: disabled ? 0.5 : pressed ? 0.85 : 1 },
      ]}
      {...props}
    >
      {loading ? <ActivityIndicator color={fg} /> : <Text style={[styles.buttonText, { color: fg }]}>{title}</Text>}
    </Pressable>
  );
}

export function Card({ style, ...props }: ViewProps) {
  const t = useTheme();
  return <View style={[styles.card, { backgroundColor: t.bg, borderColor: t.border }, style]} {...props} />;
}

export function ErrorText({ children }: { children?: string | null }) {
  const t = useTheme();
  if (!children) return null;
  return (
    <View style={[styles.error, { backgroundColor: t.dangerSoft }]} accessibilityRole="alert">
      <Text style={{ color: t.danger, fontSize: 14 }}>{children}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  button: { height: 52, borderRadius: 12, borderWidth: 1, alignItems: "center", justifyContent: "center", paddingHorizontal: 16 },
  buttonText: { fontSize: 16, fontWeight: "600" },
  card: { borderWidth: 1, borderRadius: 14, padding: 16 },
  error: { borderRadius: 10, padding: 12 },
});
