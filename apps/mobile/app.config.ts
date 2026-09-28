import { existsSync } from "node:fs";
import type { ConfigContext, ExpoConfig } from "expo/config";

/**
 * app.json plus what depends on the build: Firebase's google-services.json (Android pushes) is
 * used only when present, from GOOGLE_SERVICES_JSON (an EAS file secret) or ./google-services.json,
 * so a checkout without Firebase still builds and runs.
 */
export default ({ config }: ConfigContext): ExpoConfig => {
  const googleServices = process.env.GOOGLE_SERVICES_JSON ?? (existsSync("./google-services.json") ? "./google-services.json" : undefined);
  return {
    ...(config as ExpoConfig),
    ios: {
      ...config.ios,
      // Sign-in approvals are time-sensitive: they break through Focus modes.
      entitlements: { ...config.ios?.entitlements, "com.apple.developer.usernotifications.time-sensitive": true },
    },
    android: { ...config.android, ...(googleServices ? { googleServicesFile: googleServices } : {}) },
  };
};
