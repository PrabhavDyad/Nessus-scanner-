import { Platform } from "react-native";

export const COLORS = {
  bg: "#09090B",
  surface: "#18181B",
  surfaceAlt: "#0F0F11",
  primary: "#10B981",
  primaryDim: "#059669",
  textPrimary: "#F4F4F5",
  textSecondary: "#A1A1AA",
  border: "#27272A",
  borderActive: "rgba(16, 185, 129, 0.5)",
  severity: {
    critical: "#EF4444",
    high: "#F97316",
    medium: "#EAB308",
    low: "#3B82F6",
    info: "#6366F1",
  },
};

export const FONTS = {
  mono: Platform.select({
    ios: "Menlo",
    android: "monospace",
    default: "monospace",
  }) as string,
  body: Platform.select({
    ios: "System",
    android: "sans-serif",
    default: "System",
  }) as string,
};

export const sevColor = (sev: string): string => {
  const s = (sev || "").toLowerCase();
  return (COLORS.severity as any)[s] || COLORS.severity.info;
};
