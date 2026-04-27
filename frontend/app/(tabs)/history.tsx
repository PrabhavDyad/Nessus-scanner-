import React, { useCallback, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TouchableOpacity,
  RefreshControl,
  ActivityIndicator,
} from "react-native";
import { useFocusEffect, useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { COLORS, FONTS, sevColor } from "../../src/theme";

const API_URL = process.env.EXPO_PUBLIC_BACKEND_URL;

type Scan = {
  id: string;
  target: string;
  scan_type: string;
  scan_label: string;
  status: string;
  created_at: string;
  duration_sec?: number;
  summary?: { hosts_up?: number; open_ports?: number; total_hosts?: number };
  vuln_hints?: { severity: string }[];
};

const statusColor = (s: string): string => {
  if (s === "completed") return COLORS.primary;
  if (s === "running") return COLORS.severity.medium;
  if (s === "queued") return COLORS.severity.low;
  if (s === "failed") return COLORS.severity.critical;
  return COLORS.textSecondary;
};

const fmtTime = (iso: string) => {
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
};

const topSeverity = (hints?: { severity: string }[]): string | null => {
  if (!hints || hints.length === 0) return null;
  const order = ["critical", "high", "medium", "low", "info"];
  for (const sev of order) {
    if (hints.some((h) => h.severity === sev)) return sev;
  }
  return null;
};

export default function HistoryScreen() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = async () => {
    try {
      const r = await fetch(`${API_URL}/api/scans`);
      const data = await r.json();
      setScans(data || []);
    } catch (e) {
      console.log("history err", e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useFocusEffect(
    useCallback(() => {
      setLoading(true);
      load();
    }, [])
  );

  const onRefresh = () => {
    setRefreshing(true);
    load();
  };

  const renderItem = ({ item }: { item: Scan }) => {
    const sev = topSeverity(item.vuln_hints);
    return (
      <TouchableOpacity
        testID={`history-item-${item.id}`}
        onPress={() => router.push(`/scan/${item.id}`)}
        style={styles.card}
        activeOpacity={0.85}
      >
        <View style={styles.cardHeader}>
          <Text style={styles.target} numberOfLines={1}>
            {item.target}
          </Text>
          <View style={[styles.statusPill, { borderColor: statusColor(item.status) }]}>
            <View style={[styles.statusDot, { backgroundColor: statusColor(item.status) }]} />
            <Text style={[styles.statusText, { color: statusColor(item.status) }]}>
              {item.status.toUpperCase()}
            </Text>
          </View>
        </View>
        <Text style={styles.scanLabel}>{item.scan_label}</Text>
        <View style={styles.metaRow}>
          <View style={styles.metaItem}>
            <Ionicons name="time-outline" size={12} color={COLORS.textSecondary} />
            <Text style={styles.metaText}>{fmtTime(item.created_at)}</Text>
          </View>
          {item.duration_sec != null && (
            <View style={styles.metaItem}>
              <Ionicons name="speedometer-outline" size={12} color={COLORS.textSecondary} />
              <Text style={styles.metaText}>{item.duration_sec.toFixed(1)}s</Text>
            </View>
          )}
        </View>
        {item.status === "completed" && (
          <View style={styles.summaryRow}>
            <Text style={styles.summaryItem}>
              <Text style={styles.summaryNum}>{item.summary?.hosts_up ?? 0}</Text> hosts up
            </Text>
            <Text style={styles.summaryItem}>
              <Text style={styles.summaryNum}>{item.summary?.open_ports ?? 0}</Text> open ports
            </Text>
            {sev && (
              <View
                style={[
                  styles.sevBadge,
                  { borderColor: sevColor(sev), backgroundColor: sevColor(sev) + "22" },
                ]}
              >
                <Text style={[styles.sevText, { color: sevColor(sev) }]}>{sev.toUpperCase()}</Text>
              </View>
            )}
          </View>
        )}
      </TouchableOpacity>
    );
  };

  if (loading && scans.length === 0) {
    return (
      <View style={[styles.container, styles.centered]}>
        <ActivityIndicator color={COLORS.primary} />
      </View>
    );
  }

  return (
    <FlatList
      testID="history-list"
      style={styles.container}
      contentContainerStyle={{ padding: 16, paddingBottom: 40 }}
      data={scans}
      keyExtractor={(i) => i.id}
      renderItem={renderItem}
      refreshControl={
        <RefreshControl
          refreshing={refreshing}
          onRefresh={onRefresh}
          tintColor={COLORS.primary}
          colors={[COLORS.primary]}
        />
      }
      ListEmptyComponent={
        <View style={styles.empty}>
          <Ionicons name="folder-open-outline" size={48} color={COLORS.textSecondary} />
          <Text style={styles.emptyText}>No scans yet</Text>
          <Text style={styles.emptySub}>Run your first scan from the SCAN tab</Text>
        </View>
      }
    />
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.bg },
  centered: { justifyContent: "center", alignItems: "center" },
  card: {
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 14,
    marginBottom: 10,
  },
  cardHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  target: {
    color: COLORS.textPrimary,
    fontFamily: FONTS.mono,
    fontWeight: "700",
    fontSize: 14,
    flex: 1,
    marginRight: 8,
  },
  statusPill: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderWidth: 1,
  },
  statusDot: { width: 6, height: 6, borderRadius: 3 },
  statusText: { fontSize: 10, fontWeight: "700", letterSpacing: 1 },
  scanLabel: { color: COLORS.primary, fontSize: 12, marginTop: 6, fontFamily: FONTS.mono },
  metaRow: { flexDirection: "row", gap: 14, marginTop: 8 },
  metaItem: { flexDirection: "row", alignItems: "center", gap: 4 },
  metaText: { color: COLORS.textSecondary, fontSize: 11, fontFamily: FONTS.mono },
  summaryRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 14,
    marginTop: 10,
    paddingTop: 10,
    borderTopWidth: 1,
    borderTopColor: COLORS.border,
  },
  summaryItem: { color: COLORS.textSecondary, fontSize: 11, fontFamily: FONTS.mono },
  summaryNum: { color: COLORS.textPrimary, fontWeight: "700" },
  sevBadge: {
    marginLeft: "auto",
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderWidth: 1,
  },
  sevText: { fontSize: 10, fontWeight: "800", letterSpacing: 1 },
  empty: { alignItems: "center", marginTop: 80, gap: 8 },
  emptyText: { color: COLORS.textPrimary, fontSize: 16, fontWeight: "700", marginTop: 8 },
  emptySub: { color: COLORS.textSecondary, fontSize: 13 },
});
