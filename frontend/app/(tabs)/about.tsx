import React from "react";
import { View, Text, StyleSheet, ScrollView } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { COLORS, FONTS } from "../../src/theme";

const Row = ({ icon, title, desc }: { icon: any; title: string; desc: string }) => (
  <View style={styles.row}>
    <Ionicons name={icon} size={18} color={COLORS.primary} />
    <View style={{ flex: 1 }}>
      <Text style={styles.rowTitle}>{title}</Text>
      <Text style={styles.rowDesc}>{desc}</Text>
    </View>
  </View>
);

export default function AboutScreen() {
  return (
    <ScrollView style={styles.container} contentContainerStyle={{ padding: 16, paddingBottom: 40 }}>
      <View style={styles.banner}>
        <Text style={styles.prompt}>$ whoami</Text>
        <Text style={styles.title}>NETSCAN</Text>
        <Text style={styles.subtitle}>Mini Nessus &middot; v1.0</Text>
      </View>

      <Text style={styles.section}>// CAPABILITIES</Text>
      <Row icon="flash-outline" title="Quick Scan" desc="Top 100 ports in seconds (-T4 -F)" />
      <Row icon="globe-outline" title="Full Scan" desc="All 65535 ports (-p-)" />
      <Row icon="cube-outline" title="Service Detection" desc="Identify services & versions (-sV)" />
      <Row icon="hardware-chip-outline" title="OS Detection" desc="Fingerprint operating systems (-O)" />
      <Row icon="terminal-outline" title="Custom Flags" desc="Pass your own nmap arguments" />
      <Row icon="warning-outline" title="Vuln Hints" desc="Nessus-style severity findings" />

      <Text style={styles.section}>// HOW IT WORKS</Text>
      <View style={styles.codeBlock}>
        <Text style={styles.codeLine}>
          <Text style={styles.codePrompt}>1. </Text>Target sent to FastAPI backend
        </Text>
        <Text style={styles.codeLine}>
          <Text style={styles.codePrompt}>2. </Text>Python subprocess invokes nmap
        </Text>
        <Text style={styles.codeLine}>
          <Text style={styles.codePrompt}>3. </Text>XML output parsed into hosts/ports
        </Text>
        <Text style={styles.codeLine}>
          <Text style={styles.codePrompt}>4. </Text>Heuristics flag risky services
        </Text>
        <Text style={styles.codeLine}>
          <Text style={styles.codePrompt}>5. </Text>Results stored in MongoDB
        </Text>
      </View>

      <Text style={styles.section}>// LEGAL</Text>
      <View style={styles.warning}>
        <Ionicons name="shield-outline" size={18} color={COLORS.severity.medium} />
        <Text style={styles.warningText}>
          Scan only systems you own or are explicitly authorised to test.
          Unauthorised scanning may violate the Computer Fraud and Abuse Act
          (USA), Computer Misuse Act (UK), or equivalent laws in your country.
        </Text>
      </View>

      <Text style={styles.footer}>Built with Expo + FastAPI + nmap</Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.bg },
  banner: {
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 18,
    marginBottom: 18,
  },
  prompt: { color: COLORS.primary, fontFamily: FONTS.mono, fontSize: 12, marginBottom: 4 },
  title: {
    color: COLORS.textPrimary,
    fontFamily: FONTS.mono,
    fontSize: 28,
    fontWeight: "800",
    letterSpacing: 3,
  },
  subtitle: { color: COLORS.textSecondary, marginTop: 6, fontFamily: FONTS.mono, fontSize: 12 },
  section: {
    color: COLORS.primary,
    fontFamily: FONTS.mono,
    fontSize: 11,
    letterSpacing: 1.5,
    marginTop: 18,
    marginBottom: 10,
  },
  row: {
    flexDirection: "row",
    gap: 12,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderWidth: 1,
    borderColor: COLORS.border,
    backgroundColor: COLORS.surface,
    marginBottom: 6,
    alignItems: "flex-start",
  },
  rowTitle: { color: COLORS.textPrimary, fontWeight: "700", fontSize: 14 },
  rowDesc: { color: COLORS.textSecondary, fontSize: 12, marginTop: 2 },
  codeBlock: {
    backgroundColor: "#000",
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 12,
  },
  codeLine: { color: COLORS.textPrimary, fontFamily: FONTS.mono, fontSize: 12, lineHeight: 20 },
  codePrompt: { color: COLORS.primary },
  warning: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 10,
    padding: 12,
    borderWidth: 1,
    borderColor: "rgba(234,179,8,0.3)",
    backgroundColor: "rgba(234,179,8,0.08)",
  },
  warningText: { color: COLORS.textSecondary, fontSize: 12, flex: 1, lineHeight: 17 },
  footer: {
    color: COLORS.textSecondary,
    textAlign: "center",
    marginTop: 24,
    fontFamily: FONTS.mono,
    fontSize: 11,
  },
});
