import React, { useEffect, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  TextInput,
  TouchableOpacity,
  ScrollView,
  KeyboardAvoidingView,
  Platform,
  ActivityIndicator,
  Alert,
} from "react-native";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { COLORS, FONTS } from "../../src/theme";

const API_URL = process.env.EXPO_PUBLIC_BACKEND_URL;

type ScanType = {
  key: string;
  label: string;
  flags: string[];
};

const SCAN_TYPE_DESCRIPTIONS: Record<string, string> = {
  quick: "Top 100 ports, fast (-T4 -F)",
  full: "All 65535 ports (-p-)",
  service: "Service & version detection (-sV)",
  os: "OS fingerprinting (-O)",
  intense: "Aggressive scan (-A)",
  custom: "Use your own nmap flags",
};

export default function ScanScreen() {
  const router = useRouter();
  const [target, setTarget] = useState("scanme.nmap.org");
  const [selected, setSelected] = useState<string>("quick");
  const [customFlags, setCustomFlags] = useState("-T4 -F");
  const [scanTypes, setScanTypes] = useState<ScanType[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [nmapInstalled, setNmapInstalled] = useState<boolean | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const r1 = await fetch(`${API_URL}/api/`);
        const j1 = await r1.json();
        setNmapInstalled(j1.nmap_installed);
        const r2 = await fetch(`${API_URL}/api/scan-types`);
        const j2 = await r2.json();
        setScanTypes(j2);
      } catch (e) {
        console.log("init err", e);
      }
    })();
  }, []);

  const startScan = async () => {
    if (!target.trim()) {
      Alert.alert("Missing target", "Enter an IP, hostname, or CIDR.");
      return;
    }
    setSubmitting(true);
    try {
      const res = await fetch(`${API_URL}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          scan_type: selected,
          custom_flags: selected === "custom" ? customFlags : null,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        Alert.alert("Scan failed", data.detail || "Could not start scan.");
        return;
      }
      router.push(`/scan/${data.id}`);
    } catch (e: any) {
      Alert.alert("Network error", e?.message || "Could not reach backend.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <KeyboardAvoidingView
      style={styles.flex}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <ScrollView
        style={styles.container}
        contentContainerStyle={{ paddingBottom: 40 }}
        keyboardShouldPersistTaps="handled"
      >
        <View style={styles.heroBox} testID="hero-box">
          <Text style={styles.heroPrompt}>$ netscan --init</Text>
          <Text style={styles.heroTitle}>MINI NESSUS</Text>
          <Text style={styles.heroSub}>
            Mobile network reconnaissance powered by Nmap
          </Text>
          <View style={styles.statusRow}>
            <View
              style={[
                styles.statusDot,
                {
                  backgroundColor:
                    nmapInstalled === null
                      ? COLORS.textSecondary
                      : nmapInstalled
                      ? COLORS.primary
                      : COLORS.severity.critical,
                },
              ]}
            />
            <Text style={styles.statusText} testID="nmap-status">
              {nmapInstalled === null
                ? "checking nmap..."
                : nmapInstalled
                ? "nmap engine online"
                : "nmap NOT installed"}
            </Text>
          </View>
        </View>

        <Text style={styles.label}>// TARGET</Text>
        <TextInput
          testID="target-input"
          value={target}
          onChangeText={setTarget}
          placeholder="192.168.1.1 / scanme.nmap.org / 10.0.0.0/24"
          placeholderTextColor={COLORS.textSecondary}
          autoCapitalize="none"
          autoCorrect={false}
          style={styles.input}
        />

        <Text style={styles.label}>// SCAN TYPE</Text>
        <View style={styles.typeGrid}>
          {scanTypes.map((t) => {
            const active = selected === t.key;
            return (
              <TouchableOpacity
                key={t.key}
                testID={`scan-type-${t.key}`}
                onPress={() => setSelected(t.key)}
                style={[styles.typeCard, active && styles.typeCardActive]}
                activeOpacity={0.8}
              >
                <View style={styles.typeHeader}>
                  <Text
                    style={[styles.typeLabel, active && { color: COLORS.primary }]}
                  >
                    {t.label}
                  </Text>
                  {active && (
                    <Ionicons name="radio-button-on" size={16} color={COLORS.primary} />
                  )}
                </View>
                <Text style={styles.typeDesc}>
                  {SCAN_TYPE_DESCRIPTIONS[t.key] || t.flags.join(" ")}
                </Text>
                {t.key !== "custom" && (
                  <Text style={styles.typeFlags}>{t.flags.join(" ")}</Text>
                )}
              </TouchableOpacity>
            );
          })}
        </View>

        {selected === "custom" && (
          <>
            <Text style={styles.label}>// CUSTOM FLAGS</Text>
            <TextInput
              testID="custom-flags-input"
              value={customFlags}
              onChangeText={setCustomFlags}
              placeholder="-T4 -sV --top-ports 100"
              placeholderTextColor={COLORS.textSecondary}
              autoCapitalize="none"
              autoCorrect={false}
              style={[styles.input, { fontFamily: FONTS.mono }]}
            />
            <Text style={styles.helperText}>
              Shell metacharacters are blocked. Don&apos;t use ; &amp; | $ etc.
            </Text>
          </>
        )}

        <TouchableOpacity
          testID="start-scan-btn"
          onPress={startScan}
          disabled={submitting || nmapInstalled === false}
          style={[
            styles.cta,
            (submitting || nmapInstalled === false) && { opacity: 0.5 },
          ]}
          activeOpacity={0.85}
        >
          {submitting ? (
            <ActivityIndicator color={COLORS.bg} />
          ) : (
            <>
              <Ionicons name="flash" size={18} color={COLORS.bg} />
              <Text style={styles.ctaText}>EXECUTE SCAN</Text>
            </>
          )}
        </TouchableOpacity>

        <View style={styles.disclaimerBox}>
          <Ionicons name="warning-outline" size={16} color={COLORS.severity.medium} />
          <Text style={styles.disclaimer}>
            Only scan systems you own or have explicit permission to test.
            Unauthorised scanning may be illegal.
          </Text>
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: COLORS.bg },
  container: { flex: 1, backgroundColor: COLORS.bg, paddingHorizontal: 16 },
  heroBox: {
    borderWidth: 1,
    borderColor: COLORS.border,
    backgroundColor: COLORS.surface,
    padding: 18,
    marginTop: 12,
    marginBottom: 20,
  },
  heroPrompt: {
    color: COLORS.primary,
    fontFamily: FONTS.mono,
    fontSize: 12,
    marginBottom: 6,
  },
  heroTitle: {
    color: COLORS.textPrimary,
    fontFamily: FONTS.mono,
    fontWeight: "800",
    fontSize: 28,
    letterSpacing: 2,
  },
  heroSub: {
    color: COLORS.textSecondary,
    marginTop: 6,
    fontSize: 13,
  },
  statusRow: { flexDirection: "row", alignItems: "center", marginTop: 14, gap: 8 },
  statusDot: { width: 8, height: 8, borderRadius: 4 },
  statusText: { color: COLORS.textSecondary, fontFamily: FONTS.mono, fontSize: 12 },
  label: {
    color: COLORS.primary,
    fontFamily: FONTS.mono,
    fontSize: 11,
    letterSpacing: 1.5,
    marginBottom: 8,
    marginTop: 6,
  },
  input: {
    backgroundColor: "#000",
    borderWidth: 1,
    borderColor: COLORS.border,
    color: COLORS.textPrimary,
    paddingHorizontal: 14,
    paddingVertical: 12,
    minHeight: 48,
    fontFamily: FONTS.mono,
    fontSize: 14,
    marginBottom: 18,
  },
  typeGrid: { gap: 10, marginBottom: 18 },
  typeCard: {
    borderWidth: 1,
    borderColor: COLORS.border,
    backgroundColor: COLORS.surface,
    padding: 14,
  },
  typeCardActive: {
    borderColor: COLORS.primary,
    backgroundColor: "rgba(16,185,129,0.08)",
  },
  typeHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  typeLabel: { color: COLORS.textPrimary, fontWeight: "700", fontSize: 15 },
  typeDesc: { color: COLORS.textSecondary, fontSize: 12, marginTop: 4 },
  typeFlags: {
    color: COLORS.primary,
    fontFamily: FONTS.mono,
    fontSize: 11,
    marginTop: 6,
    opacity: 0.8,
  },
  helperText: {
    color: COLORS.textSecondary,
    fontSize: 11,
    marginTop: -10,
    marginBottom: 18,
  },
  cta: {
    backgroundColor: COLORS.primary,
    paddingVertical: 16,
    alignItems: "center",
    justifyContent: "center",
    flexDirection: "row",
    gap: 10,
    marginTop: 4,
  },
  ctaText: {
    color: COLORS.bg,
    fontWeight: "800",
    letterSpacing: 2,
    fontFamily: FONTS.mono,
  },
  disclaimerBox: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 8,
    marginTop: 18,
    padding: 12,
    borderWidth: 1,
    borderColor: "rgba(234,179,8,0.3)",
    backgroundColor: "rgba(234,179,8,0.08)",
  },
  disclaimer: {
    color: COLORS.textSecondary,
    fontSize: 11,
    flex: 1,
    lineHeight: 16,
  },
});
