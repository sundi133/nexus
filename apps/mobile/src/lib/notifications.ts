import Constants, { ExecutionEnvironment } from "expo-constants";
import { Platform } from "react-native";

type NotificationsModule = typeof import("expo-notifications");

/**
 * Push notifications, where the app can have them. Expo Go on Android removed them (SDK 53), and
 * even loading expo-notifications there throws, so the module isn't loaded at all: the app polls
 * for approvals and notifications instead while it's open.
 */
export const pushSupported = !(Platform.OS === "android" && Constants.executionEnvironment === ExecutionEnvironment.StoreClient);

export const Notifications: NotificationsModule | null = pushSupported ? (require("expo-notifications") as NotificationsModule) : null;

/**
 * Android notification channels, matching what the server asks for per notification (see
 * pushChannel in the API): sign-in approvals pop up and buzz, requests to approve are high
 * priority, everything else is normal. People can tune each in Android's settings.
 */
export async function setUpChannels() {
  if (!Notifications || Platform.OS !== "android") return;
  const { AndroidImportance } = Notifications;
  await Notifications.setNotificationChannelAsync("sign-ins", { name: "Sign-in approvals", importance: AndroidImportance.MAX, vibrationPattern: [0, 250, 250, 250], lightColor: "#4F46E5" });
  await Notifications.setNotificationChannelAsync("approvals", { name: "Requests to approve", importance: AndroidImportance.HIGH });
  await Notifications.setNotificationChannelAsync("updates", { name: "Updates", importance: AndroidImportance.DEFAULT });
}
