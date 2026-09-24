import { ApiProblem, createClient, unwrap } from "@nexus/api-client";
import Constants from "expo-constants";
import { Platform } from "react-native";

/** Same generated client as the web console, pointed at the API this phone was paired with. */
export const clientFor = (apiUrl: string, token?: string) =>
  createClient({
    baseUrl: apiUrl.replace(/\/+$/, ""),
    getToken: () => token,
    clientId: `${Platform.OS}/${Constants.expoConfig?.version ?? "dev"}`,
  });

export type Api = ReturnType<typeof clientFor>;
export { ApiProblem, unwrap };

export const errorMessage = (err: unknown) =>
  err instanceof ApiProblem ? err.message : err instanceof Error ? err.message : "Something went wrong";
