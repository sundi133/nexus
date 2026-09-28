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
