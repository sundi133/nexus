import * as Device from "expo-device";
import * as Notifications from "expo-notifications";
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { Platform } from "react-native";
import { ApiProblem, clientFor, unwrap, type Api } from "./api";
import { generateDeviceKey } from "./keys";
import { clearPairing, loadPairing, savePairing, type Pairing } from "./store";

type State =
  | { status: "loading" }
  | { status: "unpaired" }
  | { status: "paired"; pairing: Pairing; api: Api };

type Ctx = State & {
  pair: (apiUrl: string, code: string) => Promise<void>;
  unpair: () => Promise<void>;
  /** Call when the API says this phone's session is gone (unpaired from the console, user suspended…). */
  onUnauthorized: (err: unknown) => boolean;
};

const SessionContext = createContext<Ctx | null>(null);

export function useSession() {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession outside SessionProvider");
  return ctx;
}

/** Best effort: Expo Go on Android and simulators can't get a device push token. Approvals still arrive by polling. */
async function devicePushToken(): Promise<string | undefined> {
  try {
    if (!Device.isDevice || Platform.OS === "web") return undefined;
    const perm = await Notifications.requestPermissionsAsync();
    if (!perm.granted) return undefined;
    return (await Notifications.getDevicePushTokenAsync()).data as string;
  } catch {
    return undefined;
  }
}

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    loadPairing()
      .then((p) => setState(p ? { status: "paired", pairing: p, api: clientFor(p.apiUrl, p.token) } : { status: "unpaired" }))
      .catch(() => setState({ status: "unpaired" }));
  }, []);

  const pair = useCallback(async (apiUrl: string, code: string) => {
    const key = generateDeviceKey();
    const pushToken = await devicePushToken();
    const r = await unwrap(
      clientFor(apiUrl).POST("/v1/devices/pair", {
        body: {
          code,
          public_key: key.publicKey,
          device_name: Device.deviceName ?? Device.modelName ?? "My phone",
          platform: Platform.OS === "ios" ? "ios" : Platform.OS === "android" ? "android" : "web",
          push_token: pushToken,
        },
      }),
    );
    const pairing: Pairing = {
      apiUrl,
      token: r.token,
      factorId: r.factor_id,
      secretKey: key.secretKey,
      user: { email: r.user.email, displayName: r.user.display_name },
      orgName: r.organization.name,
    };
    await savePairing(pairing);
    setState({ status: "paired", pairing, api: clientFor(apiUrl, r.token) });
  }, []);

  const unpair = useCallback(async () => {
    if (state.status === "paired") {
      // Remove this phone's factor server-side too (also signs this phone out).
      await state.api.DELETE("/v1/me/factors/{id}", { params: { path: { id: state.pairing.factorId } } }).catch(() => {});
    }
    await clearPairing();
    setState({ status: "unpaired" });
  }, [state]);

  const onUnauthorized = useCallback((err: unknown) => {
    if (err instanceof ApiProblem && err.status === 401 && err.code === "unauthenticated") {
      void clearPairing().then(() => setState({ status: "unpaired" }));
      return true;
    }
    return false;
  }, []);

  const value = useMemo(() => ({ ...state, pair, unpair, onUnauthorized }), [state, pair, unpair, onUnauthorized]);
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}
