import { Stack } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { SafeAreaProvider } from "react-native-safe-area-context";

export default function RootLayout() {
  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      <Stack
        screenOptions={{
          headerStyle: { backgroundColor: "#09090B" },
          headerTintColor: "#10B981",
          headerTitleStyle: { fontWeight: "700", letterSpacing: 1 },
          contentStyle: { backgroundColor: "#09090B" },
        }}
      >
        <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
        <Stack.Screen
          name="scan/[id]"
          options={{ title: "SCAN DETAIL", headerBackTitle: "Back" }}
        />
      </Stack>
    </SafeAreaProvider>
  );
}
