import { router, Stack } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { useEffect } from "react";
import { unwrap } from "@/lib/api";
import { requestIdFromLink } from "@/lib/biometrics";
import { Notifications, setUpChannels } from "@/lib/notifications";
import { SessionProvider, useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";

void setUpChannels();
Notifications?.setNotificationHandler({
  handleNotification: async () => ({ shouldPlaySound: true, shouldSetBadge: false, shouldShowBanner: true, shouldShowList: true }),
});

/**
 * Pushes are content-free ({category, id}); tapping one opens the matching screen, which fetches
 * the details. For inbox notifications the id is the notification's: look it up for its link.
 */
function PushRouter() {
  const session = useSession();
  useEffect(() => {
    if (!Notifications) return; // no pushes here (Expo Go on Android): nothing to tap
    const sub = Notifications.addNotificationResponseReceivedListener((response) => {
      const data = response.notification.request.content.data as { category?: string; id?: string };
      if (data.category === "auth.mfa_challenge" && data.id) router.push({ pathname: "/approve/[id]", params: { id: data.id } });
      else if (data.category === "access.approval") router.push("/approvals");
      else if (data.category === "access.granted" || data.category === "access.denied" || data.category === "access.ended") router.push("/requests");
      else if (data.category === "device.app_blocked" && data.id && session.status === "paired") {
        void unwrap(session.api.GET("/v1/me/notifications", { params: { query: { limit: 50, filter: "all" } } }))
          .then((r) => {
            const request = requestIdFromLink(r.data.find((n) => n.id === data.id)?.link);
            if (request) router.push({ pathname: "/request/[id]", params: { id: request } });
          })
          .catch(() => undefined);
      }
    });
    return () => sub.remove();
  }, [session]);
  return null;
}

export default function RootLayout() {
  const t = useTheme();

  return (
    <SessionProvider>
      <PushRouter />
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
        <Stack.Screen name="approvals" options={{ title: "To approve" }} />
        <Stack.Screen name="request/[id]" options={{ title: "Request access", presentation: "modal" }} />
        <Stack.Screen name="codes" options={{ title: "Authenticator codes" }} />
        <Stack.Screen name="requests" options={{ title: "My requests" }} />
        <Stack.Screen name="catalog" options={{ title: "Ask for access" }} />
      </Stack>
    </SessionProvider>
  );
}
