import { useColorScheme } from "react-native";

// Mirrors the web design tokens (apps/web/src/app/globals.css) so both clients look like one product.
const light = {
  bg: "#FFFFFF",
  bgSubtle: "#F7F7F8",
  bgMuted: "#F0F1F3",
  border: "#E6E7EA",
  fg: "#0F1115",
  fgMuted: "#5B606B",
  fgSubtle: "#8A909B",
  primary: "#4F46E5",
  primaryFg: "#FFFFFF",
  primarySoft: "#EEF2FF",
  success: "#16A34A",
  warning: "#D97706",
  danger: "#DC2626",
  dangerSoft: "#FEF2F2",
};
const dark: typeof light = {
  bg: "#0B0C0E",
  bgSubtle: "#111316",
  bgMuted: "#181A1E",
  border: "#23262B",
  fg: "#EDEEF0",
  fgMuted: "#9097A3",
  fgSubtle: "#6B717C",
  primary: "#818CF8",
  primaryFg: "#0B0C0E",
  primarySoft: "#1E1B4B",
  success: "#4ADE80",
  warning: "#FBBF24",
  danger: "#F87171",
  dangerSoft: "#2A0B0B",
};

export type Theme = typeof light;
export const useTheme = (): Theme => (useColorScheme() === "dark" ? dark : light);
