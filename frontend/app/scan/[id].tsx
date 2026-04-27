import React, { useEffect, useRef, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
  TouchableOpacity,
  Alert,
} from "react-native";
import { useLocalSearchParams, useRouter, Stack } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { COLORS, FONTS, sevColor } from "../../src/theme";

const API_URL = process.env.EXPO_PUBLIC_BACKEND_URL;

type Port = {
  port: number;
  protocol: string;
  state: string;
  service?: string;
  product?: string;
  version?: string;
  extrainfo?: string;
};

type Host = {
  address: string;
  hostname?: string;
  state: string;
  os_guess?: string;
  ports: Port[];
};

type Hint = {
  severity: string;
  title: string;
  description: string;
  port?: number;
};

type Scan = {
  id: string;
  target: string;
  scan_type: string;
  scan_label: string;
  flags: string[];
  status: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  duration_sec?: number;
  raw_output: string;
  error?: string;
  hosts: Host[];
  vuln_hints: Hint[];
  summary: { hosts_up?: number; open_ports?: number; total_hosts?: number; hosts_down?: number };
};

const ASCII_FRAMES = [
  "[=         ]",
  "[==        ]",
  "[===       ]",
  "[====      ]",
  "[=====     ]",
  "[======    ]",
  "[=======   ]",
  "[========  ]",
  "[========= ]",
  "[==========]",
];

export default function ScanDetail() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const router = useRouter();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [frame, setFrame] = useState(0);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchScan = async () => {
    try {
      const r = await fetch(`${API_URL}/api/scans/${id}`);
      if (!r.ok) {
        if (r.status === 404) {
          Alert.alert("Not found", "This scan no longer exists.");
          router.back();
          return;
        }
        throw new Error(`HTTP ${r.status}`);
      }
      const data: Scan = await r.json();
      setScan(data);
      setLoading(false);
      if (data.status === "running" || data.status === "queued") {
        pollRef.current = setTimeout(fetchScan, 1500);
      }
    } catch (e) {
      console.log("fetchScan err", e);
      pollRef.current = setTimeout(fetchScan, 3000);
    }
  };

  useEffect(() => {
    fetchScan();
    const t = setInterval(() => setFrame((f) => (f + 1) % ASCII_FRAMES.length), 200);
    return () => {
      if (pollRef.current) clearTimeout(pollRef.current);
      clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const onDelete = async () => {
    if (!scan) return;
    Alert.alert("Delete scan?", "This cannot be undone.", [
      { text: "Cancel", style: "cancel" },
      {
        text: "Delete",
        style: "destructive",
        onPress: async () => {
          await fetch(`${API_URL}/api/scans/${scan.id}`, { method: "DELETE" });
          router.back();
        },
      },
    ]);
  };

  if (loading || !scan) {
    return (
      <View style={[styles.container, styles.centered]}>
        <Stack.Screen options={{ title: "LOADING..." }} />
        <ActivityIndicator color={COLORS.primary} />
      </View>
    );
  }

  const isRunning = scan.status === "running" || scan.status === "queued";
  const totalOpen = scan.summary?.open_ports ?? 0;
  const totalHosts = scan.summary?.total_hosts ?? scan.hosts.length;

  return (
    <ScrollView style={styles.container} contentContainerStyle={{ padding: 16, paddingBottom: 40 }}>
      <Stack.Screen
        options={{
          title: "// SCAN",
          headerRight: () => (
            <TouchableOpacity onPress={onDelete} testID="delete-scan-btn" style={{ paddingHorizontal: 12 }}>
              <Ionicons name="trash-outline" size={20} color={COLORS.severity.critical} />
            </TouchableOpacity>
          ),
        }}
      />

      <View style={styles.headerCard}>
        <Text style={styles.target} testID="scan-target" numberOfLines={2}>
          {scan.target}
        </Text>
        <Text style={styles.scanType}>{scan.scan_label}</Text>
        <Text style={styles.flags}>$ nmap {scan.flags.join(" ")} {scan.target}</Text>

        <View style={styles.statusBox}>
          <View style={[styles.dot, { backgroundColor: statusColor(scan.status) }]} />
          <Text style={[styles.statusLabel, { color: statusColor(scan.status) }]} testID="scan-status">
            {scan.status.toUpperCase()}
          </Text>
          {isRunning && (
            <Text style={styles.progressFrame}>{ASCII_FRAMES[frame]}</Text>
          )}
          {scan.duration_sec != null && (
            <Text style={styles.duration}>{scan.duration_sec.toFixed(1)}s</Text>
          )}
        </View>

        {scan.status === "completed" && (
          <View style={styles.statRow}>
            <Stat label="HOSTS" value={`${scan.summary?.hosts_up ?? 0}/${totalHosts}`} />
            <Stat label="OPEN PORTS" value={String(totalOpen)} />
            <Stat label="FINDINGS" value={String(scan.vuln_hints.length)} />
          </View>
        )}
      </View>

      {scan.status === "failed" && scan.error && (
        <View style={styles.errorBox}>
          <Text style={styles.errorTitle}>SCAN FAILED</Text>
          <Text style={styles.errorText}>{scan.error}</Text>
        </View>
      )}

      {scan.status === "completed" && scan.vuln_hints.length > 0 && (
        <>
          <Text style={styles.section}>// FINDINGS</Text>
          {scan.vuln_hints.map((h, i) => (
            <View
              key={i}
              testID={`finding-${i}`}
              style={[
                styles.findingCard,
                { borderColor: sevColor(h.severity) },
              ]}
            >
              <View style={styles.findingHeader}>
                <View
                  style={[
                    styles.sevBadge,
                    { borderColor: sevColor(h.severity), backgroundColor: sevColor(h.severity) + "22" },
                  ]}
                >
                  <Text style={[styles.sevText, { color: sevColor(h.severity) }]}>
                    {h.severity.toUpperCase()}
                  </Text>
                </View>
                {h.port && <Text style={styles.findingPort}>:{h.port}</Text>}
              </View>
              <Text style={styles.findingTitle}>{h.title}</Text>
              <Text style={styles.findingDesc}>{h.description}</Text>
            </View>
          ))}
        </>
      )}

      {scan.status === "completed" && scan.hosts.length > 0 && (
        <>
          <Text style={styles.section}>// HOSTS &amp; PORTS</Text>
          {scan.hosts.map((host, hi) => (
            <View key={hi} style={styles.hostCard} testID={`host-${hi}`}>
              <View style={styles.hostHeader}>
                <Text style={styles.hostAddr}>{host.address}</Text>
                <View
                  style={[
                    styles.statePill,
                    {
                      borderColor: host.state === "up" ? COLORS.primary : COLORS.severity.critical,
                    },
                  ]}
                >
                  <Text
                    style={[
                      styles.statePillText,
                      { color: host.state === "up" ? COLORS.primary : COLORS.severity.critical },
                    ]}
                  >
                    {host.state.toUpperCase()}
                  </Text>
                </View>
              </View>
              {host.hostname && <Text style={styles.hostMeta}>hostname: {host.hostname}</Text>}
              {host.os_guess && <Text style={styles.hostMeta}>os: {host.os_guess}</Text>}

              {host.ports.length === 0 ? (
                <Text style={styles.noPorts}>No ports reported</Text>
              ) : (
                <>
                  <View style={styles.portHead}>
                    <Text style={[styles.portCol, { flex: 1.1 }]}>PORT</Text>
                    <Text style={[styles.portCol, { flex: 1 }]}>STATE</Text>
                    <Text style={[styles.portCol, { flex: 2.5 }]}>SERVICE</Text>
                  </View>
                  {host.ports.map((p, pi) => (
                    <View key={pi} style={styles.portRow} testID={`port-${hi}-${pi}`}>
                      <Text style={[styles.portCell, { flex: 1.1 }]}>
                        {p.port}/{p.protocol}
                      </Text>
                      <Text
                        style={[
                          styles.portCell,
                          { flex: 1, color: p.state === "open" ? COLORS.primary : COLORS.textSecondary },
                        ]}
                      >
                        {p.state}
                      </Text>
                      <View style={{ flex: 2.5 }}>
                        <Text style={styles.portCell}>{p.service || "-"}</Text>
                        {(p.product || p.version) && (
                          <Text style={styles.portVersion} numberOfLines={2}>
                            {[p.product, p.version, p.extrainfo].filter(Boolean).join(" ")}
                          </Text>
                        )}
                      </View>
                    </View>
                  ))}
                </>
              )}
            </View>
          ))}
        </>
      )}

      {(isRunning || scan.raw_output) && (
        <>
          <Text style={styles.section}>// RAW OUTPUT</Text>
          <View style={styles.terminal}>
            {isRunning ? (
              <Text style={styles.terminalLine}>
                running nmap {scan.flags.join(" ")} {scan.target} {ASCII_FRAMES[frame]}
              </Text>
            ) : (
              <Text style={styles.terminalLine} testID="raw-output" selectable>
                {scan.raw_output || "(empty)"}
              </Text>
            )}
          </View>
        </>
      )}
    </ScrollView>
  );
}

const Stat = ({ label, value }: { label: string; value: string }) => (
  <View style={styles.stat}>
    <Text style={styles.statValue}>{value}</Text>
    <Text style={styles.statLabel}>{label}</Text>
  </View>
);

const statusColor = (s: string): string => {
  if (s === "completed") return COLORS.primary;
  if (s === "running") return COLORS.severity.medium;
  if (s === "queued") return COLORS.severity.low;
  if (s === "failed") return COLORS.severity.critical;
  return COLORS.textSecondary;
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.bg },
  centered: { justifyContent: "center", alignItems: "center" },
  headerCard: {
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 14,
    marginBottom: 16,
  },
  target: {
    color: COLORS.textPrimary,
    fontFamily: FONTS.mono,
    fontWeight: "800",
    fontSize: 18,
  },
  scanType: { color: COLORS.primary, fontSize: 12, marginTop: 4, fontFamily: FONTS.mono },
  flags: { color: COLORS.textSecondary, fontFamily: FONTS.mono, fontSize: 11, marginTop: 8 },
  statusBox: { flexDirection: "row", alignItems: "center", gap: 8, marginTop: 12 },
  dot: { width: 8, height: 8, borderRadius: 4 },
  statusLabel: { fontFamily: FONTS.mono, fontWeight: "800", letterSpacing: 1, fontSize: 12 },
  progressFrame: { color: COLORS.primary, fontFamily: FONTS.mono, fontSize: 12 },
  duration: { color: COLORS.textSecondary, fontFamily: FONTS.mono, fontSize: 11, marginLeft: "auto" },
  statRow: {
    flexDirection: "row",
    marginTop: 14,
    paddingTop: 14,
    borderTopWidth: 1,
    borderTopColor: COLORS.border,
    gap: 10,
  },
  stat: { flex: 1, alignItems: "flex-start" },
  statValue: { color: COLORS.primary, fontFamily: FONTS.mono, fontSize: 20, fontWeight: "800" },
  statLabel: { color: COLORS.textSecondary, fontSize: 10, fontFamily: FONTS.mono, letterSpacing: 1, marginTop: 2 },
  errorBox: {
    borderWidth: 1,
    borderColor: COLORS.severity.critical,
    backgroundColor: "rgba(239,68,68,0.08)",
    padding: 14,
    marginBottom: 16,
  },
  errorTitle: {
    color: COLORS.severity.critical,
    fontFamily: FONTS.mono,
    fontWeight: "800",
    letterSpacing: 1,
    fontSize: 12,
    marginBottom: 6,
  },
  errorText: { color: COLORS.textPrimary, fontFamily: FONTS.mono, fontSize: 12 },
  section: {
    color: COLORS.primary,
    fontFamily: FONTS.mono,
    fontSize: 11,
    letterSpacing: 1.5,
    marginTop: 8,
    marginBottom: 10,
  },
  findingCard: {
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderLeftWidth: 4,
    padding: 12,
    marginBottom: 8,
  },
  findingHeader: { flexDirection: "row", alignItems: "center", gap: 8, marginBottom: 6 },
  sevBadge: { paddingHorizontal: 8, paddingVertical: 3, borderWidth: 1 },
  sevText: { fontSize: 10, fontWeight: "800", letterSpacing: 1 },
  findingPort: { color: COLORS.textSecondary, fontFamily: FONTS.mono, fontSize: 11 },
  findingTitle: { color: COLORS.textPrimary, fontWeight: "700", fontSize: 14 },
  findingDesc: { color: COLORS.textSecondary, fontSize: 12, marginTop: 4, lineHeight: 17 },
  hostCard: {
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 12,
    marginBottom: 10,
  },
  hostHeader: { flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  hostAddr: { color: COLORS.textPrimary, fontFamily: FONTS.mono, fontWeight: "800", fontSize: 14 },
  statePill: { paddingHorizontal: 8, paddingVertical: 3, borderWidth: 1 },
  statePillText: { fontSize: 10, fontWeight: "800", letterSpacing: 1 },
  hostMeta: { color: COLORS.textSecondary, fontFamily: FONTS.mono, fontSize: 11, marginTop: 4 },
  noPorts: { color: COLORS.textSecondary, fontStyle: "italic", marginTop: 10, fontSize: 12 },
  portHead: {
    flexDirection: "row",
    paddingVertical: 6,
    marginTop: 10,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },
  portCol: { color: COLORS.primary, fontFamily: FONTS.mono, fontSize: 10, letterSpacing: 1 },
  portRow: {
    flexDirection: "row",
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: "#1f1f23",
    alignItems: "flex-start",
  },
  portCell: { color: COLORS.textPrimary, fontFamily: FONTS.mono, fontSize: 12 },
  portVersion: { color: COLORS.textSecondary, fontFamily: FONTS.mono, fontSize: 10, marginTop: 2 },
  terminal: {
    backgroundColor: "#000",
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 12,
    marginBottom: 16,
  },
  terminalLine: { color: COLORS.primary, fontFamily: FONTS.mono, fontSize: 11, lineHeight: 16 },
});
