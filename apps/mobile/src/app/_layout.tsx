import * as Notifications from "expo-notifications";
import { router, Stack } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { useEffect } from "react";
import { SessionProvider } from "@/lib/session";
import { useTheme } from "@/lib/theme";

Notifications.setNotificationHandler({
  handleNotification: async () => ({ shouldPlaySound: true, shouldSetBadge: false, shouldShowBanner: true, shouldShowList: true }),
});

export default function RootLayout() {
  const t = useTheme();

  // Pushes are content-free ({category, id}); tapping one opens the matching screen, which fetches details.
  useEffect(() => {
    const sub = Notifications.addNotificationResponseReceivedListener((response) => {
      const data = response.notification.request.content.data as { category?: string; id?: string };
      if (data.category === "auth.mfa_challenge" && data.id) router.push({ pathname: "/approve/[id]", params: { id: data.id } });
    });
    return () => sub.remove();
  }, []);

  return (
    <SessionProvider>
      <StatusBar style="auto" />
      <Stack
        screenOptions={{
          headerStyle: { backgroundColor: t.bg },
          headerTintColor: t.fg,
          headerShadowVisible: false,
          contentStyle: { backgroundColor: t.bgSubtle },
        }}
      >
        <Stack.Screen name="index" options={{ title: "Nexus" }} />
        <Stack.Screen name="pair" options={{ title: "Pair with Nexus" }} />
        <Stack.Screen name="approve/[id]" options={{ title: "Sign-in request", presentation: "fullScreenModal", gestureEnabled: false }} />
      </Stack>
    </SessionProvider>
  );
}
