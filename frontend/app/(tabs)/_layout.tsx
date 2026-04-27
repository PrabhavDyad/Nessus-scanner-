import { Tabs } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { Platform } from "react-native";

export default function TabsLayout() {
  return (
    <Tabs
      screenOptions={{
        tabBarStyle: {
          backgroundColor: "#09090B",
          borderTopColor: "#27272A",
          borderTopWidth: 1,
          height: Platform.OS === "ios" ? 86 : 64,
          paddingTop: 6,
        },
        tabBarActiveTintColor: "#10B981",
        tabBarInactiveTintColor: "#71717A",
        tabBarLabelStyle: { fontSize: 11, letterSpacing: 1, fontWeight: "600" },
        headerStyle: { backgroundColor: "#09090B" },
        headerTintColor: "#10B981",
        headerTitleStyle: { fontWeight: "700", letterSpacing: 2 },
        headerShadowVisible: false,
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: "SCAN",
          headerTitle: "// NETSCAN",
          tabBarIcon: ({ color, size }) => (
            <Ionicons name="scan-outline" size={size} color={color} />
          ),
        }}
      />
      <Tabs.Screen
        name="history"
        options={{
          title: "HISTORY",
          headerTitle: "// HISTORY",
          tabBarIcon: ({ color, size }) => (
            <Ionicons name="time-outline" size={size} color={color} />
          ),
        }}
      />
      <Tabs.Screen
        name="about"
        options={{
          title: "ABOUT",
          headerTitle: "// ABOUT",
          tabBarIcon: ({ color, size }) => (
            <Ionicons name="information-circle-outline" size={size} color={color} />
          ),
        }}
      />
    </Tabs>
  );
}
