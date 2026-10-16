import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Switch,
  Alert,
  AppState,
  RefreshControl,
} from 'react-native';
import { Colors } from '../theme/colors';
import {
  GuardAlert,
  GuardStatus,
  clearAlerts,
  deleteAlert,
  getAlerts,
  getGuardStatus,
  openNotificationAccessSettings,
  requestGuardPermissions,
  setGuardEnabled,
  simulateAlert,
} from '../services/guardBridge';
import { profileSender, SENDER_DISCLAIMER } from '../services/senderProfile';
import { analyzeSuspiciousContent } from '../services/heuristicEngine';
import { ResultCard } from '../components/ResultCard';
import { ReportPanel } from '../components/ReportPanel';
import { EmergencyBanner } from '../components/EmergencyBanner';

interface ShieldScreenProps {
  /** Alert to open directly (from a notification tap). */
  focusAlertId?: string | null;
  onFocusHandled?: () => void;
}

const DEMO_SMS =
  'Dear customer your SBI account will be BLOCKED today. Update KYC immediately at http://sbi-kyc-update.xyz/login or share OTP with officer 9876543210.';

export const ShieldScreen: React.FC<ShieldScreenProps> = ({ focusAlertId, onFocusHandled }) => {
  const [status, setStatus] = useState<GuardStatus | null>(null);
  const [alerts, setAlerts] = useState<GuardAlert[]>([]);
  const [selected, setSelected] = useState<GuardAlert | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(async () => {
    const [s, a] = await Promise.all([getGuardStatus(), getAlerts()]);
    setStatus(s);
    setAlerts(a);
    return a;
  }, []);

  useEffect(() => {
    refresh();
    const sub = AppState.addEventListener('change', (st) => st === 'active' && refresh());
    return () => sub.remove();
  }, [refresh]);

  useEffect(() => {
    if (!focusAlertId) return;
    refresh().then((list) => {
      const hit = list.find((a) => a.id === focusAlertId);
      if (hit) setSelected(hit);
      onFocusHandled?.();
    });
  }, [focusAlertId, refresh, onFocusHandled]);

  const outcome = useMemo(
    () =>
      selected
        ? analyzeSuspiciousContent({ modality: 'message', content: selected.excerpt, claimedSender: selected.sender })
        : null,
    [selected]
  );

  const senderInfo = useMemo(
    () => (selected ? profileSender(selected.sender, selected.excerpt) : null),
    [selected]
  );

  if (selected && outcome) {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <TouchableOpacity onPress={() => setSelected(null)} style={styles.back}>
          <Text style={styles.backText}>← All alerts</Text>
        </TouchableOpacity>
        <View style={styles.msgBox}>
          <Text style={styles.msgMeta}>
            {selected.source}
            {selected.sender ? ` · ${selected.sender}` : ''} · {new Date(selected.receivedAt).toLocaleString('en-IN')}
          </Text>
          <Text style={styles.msgText} selectable>
            {selected.excerpt}
          </Text>
        </View>
        <View style={[styles.card, senderInfo?.suspicious && styles.senderWarn]}>
          <Text style={styles.h2}>Who sent this?</Text>
          <Text style={styles.cardText}>
            <Text style={{ fontWeight: '700' }}>{senderInfo?.label}</Text>
            {selected.sender ? `  (${selected.sender})` : ''}
            {'\n'}
            {senderInfo?.note}
            {'\n\n'}
            {SENDER_DISCLAIMER}
          </Text>
        </View>
        <ResultCard outcome={outcome} onReset={() => setSelected(null)} />
        <ReportPanel
          input={{
            source: selected.source,
            sender: selected.sender,
            receivedAt: selected.receivedAt,
            messageText: selected.excerpt,
            outcome,
          }}
        />
        <TouchableOpacity
          style={styles.deleteBtn}
          onPress={async () => {
            await deleteAlert(selected.id);
            setSelected(null);
            refresh();
          }}
        >
          <Text style={styles.deleteText}>🗑️ Delete this alert from my phone</Text>
        </TouchableOpacity>
      </ScrollView>
    );
  }

  if (status && !status.supported) {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <Text style={styles.h1}>Auto-protection</Text>
        <View style={styles.card}>
          <Text style={styles.cardText}>
            Automatic SMS, WhatsApp and email scanning needs the installed Android app (APK). It isn't available in
            Expo Go, on iPhone or on the web — Apple and browsers don't allow apps to read incoming messages.
            {'\n\n'}You can still paste or share any message into the Check tab.
          </Text>
        </View>
        <EmergencyBanner />
      </ScrollView>
    );
  }

  const allSet = !!status && status.enabled && status.smsPermission && status.notificationAccess && status.notificationPermission;

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={
        <RefreshControl
          refreshing={refreshing}
          tintColor={Colors.white}
          onRefresh={async () => {
            setRefreshing(true);
            await refresh();
            setRefreshing(false);
          }}
        />
      }
    >
      <View style={[styles.hero, allSet ? styles.heroOn : styles.heroOff]}>
        <Text style={styles.heroIcon}>{allSet ? '🛡️' : '⚠️'}</Text>
        <View style={{ flex: 1 }}>
          <Text style={styles.heroTitle}>{allSet ? 'Protection is ON' : 'Protection needs setup'}</Text>
          <Text style={styles.heroSub}>
            {allSet
              ? 'We check new SMS, WhatsApp, Gmail & Outlook messages on your phone and alert you instantly.'
              : 'Turn on the items below so JanVaani can warn you about scam messages automatically.'}
          </Text>
        </View>
        <Switch
          value={!!status?.enabled}
          onValueChange={async (v) => {
            await setGuardEnabled(v);
            refresh();
          }}
          trackColor={{ false: Colors.border, true: Colors.emerald }}
          thumbColor={Colors.white}
        />
      </View>

      <Text style={styles.h2}>Setup</Text>
      <SetupRow
        done={!!status?.smsPermission && !!status?.notificationPermission}
        title="Scan incoming SMS & show alerts"
        desc="Read-only. We never send, delete or forward your SMS."
        cta="Allow"
        onPress={async () => {
          await requestGuardPermissions();
          refresh();
        }}
      />
      <SetupRow
        done={!!status?.notificationAccess}
        title="Watch WhatsApp, Gmail, Outlook, Telegram"
        desc="Uses Android 'Notification access'. Only messaging & email apps are checked."
        cta="Open settings"
        onPress={() => {
          Alert.alert(
            'Allow notification access',
            'On the next screen, find "JanVaani" and switch it ON. Messages are checked on your phone only — nothing is uploaded.',
            [
              { text: 'Cancel', style: 'cancel' },
              { text: 'Continue', onPress: openNotificationAccessSettings },
            ]
          );
        }}
      />

      <TouchableOpacity style={styles.testBtn} onPress={() => simulateAlert(DEMO_SMS).then(() => setTimeout(refresh, 600))}>
        <Text style={styles.testText}>🧪 Send a test scam alert</Text>
      </TouchableOpacity>

      <View style={styles.listHeader}>
        <Text style={styles.h2}>Alerts ({alerts.length})</Text>
        {alerts.length > 0 && (
          <TouchableOpacity
            onPress={() =>
              Alert.alert('Delete all alerts?', 'This permanently removes all saved alerts from this phone.', [
                { text: 'Cancel', style: 'cancel' },
                {
                  text: 'Delete all',
                  style: 'destructive',
                  onPress: async () => {
                    await clearAlerts();
                    refresh();
                  },
                },
              ])
            }
          >
            <Text style={styles.clearText}>Delete all</Text>
          </TouchableOpacity>
        )}
      </View>

      {alerts.length === 0 ? (
        <View style={styles.card}>
          <Text style={styles.cardText}>
            No suspicious messages yet. When one arrives you'll get a notification instantly.
          </Text>
        </View>
      ) : (
        alerts.map((a) => (
          <TouchableOpacity key={a.id} style={styles.alertRow} onPress={() => setSelected(a)}>
            <View style={[styles.levelDot, { backgroundColor: a.level === 'HIGH' ? Colors.riskHigh : Colors.riskMedium }]} />
            <View style={{ flex: 1 }}>
              <Text style={styles.alertTitle} numberOfLines={1}>
                {a.level === 'HIGH' ? 'Likely scam' : 'Check carefully'} · {a.source}
                {a.sender ? ` · ${a.sender}` : ''}
              </Text>
              <Text style={styles.alertExcerpt} numberOfLines={2}>
                {a.excerpt}
              </Text>
              <Text style={styles.alertMeta}>
                {a.tactics.slice(0, 2).join(' • ')} · {new Date(a.receivedAt).toLocaleString('en-IN')}
              </Text>
            </View>
            <Text style={styles.chev}>›</Text>
          </TouchableOpacity>
        ))
      )}

      <Text style={styles.footnote}>
        Alerts are warning signs, not proof. They're stored encrypted on this phone only and auto-delete after 30 days.
        JanVaani never uploads your messages and never files complaints on its own.
        {'\n\n'}App by Apoorva SV
      </Text>
    </ScrollView>
  );
};

const SetupRow: React.FC<{ done: boolean; title: string; desc: string; cta: string; onPress: () => void }> = ({
  done,
  title,
  desc,
  cta,
  onPress,
}) => (
  <View style={styles.setupRow}>
    <Text style={styles.setupIcon}>{done ? '✅' : '⭕'}</Text>
    <View style={{ flex: 1 }}>
      <Text style={styles.setupTitle}>{title}</Text>
      <Text style={styles.setupDesc}>{desc}</Text>
    </View>
    {!done && (
      <TouchableOpacity style={styles.setupBtn} onPress={onPress}>
        <Text style={styles.setupBtnText}>{cta}</Text>
      </TouchableOpacity>
    )}
  </View>
);

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.background },
  content: { padding: 16, paddingBottom: 40, gap: 10 },
  h1: { color: Colors.textPrimary, fontSize: 22, fontWeight: '900' },
  h2: { color: Colors.textPrimary, fontSize: 15, fontWeight: '800', marginTop: 6 },
  hero: { flexDirection: 'row', alignItems: 'center', gap: 12, borderRadius: 18, padding: 16, borderWidth: 1 },
  heroOn: { backgroundColor: Colors.riskLowBg, borderColor: Colors.riskLowBorder },
  heroOff: { backgroundColor: Colors.riskMediumBg, borderColor: Colors.riskMediumBorder },
  heroIcon: { fontSize: 30 },
  heroTitle: { color: Colors.white, fontSize: 17, fontWeight: '900' },
  heroSub: { color: Colors.textPrimary, fontSize: 11.5, lineHeight: 16, marginTop: 2, opacity: 0.85 },
  card: { backgroundColor: Colors.surface, borderColor: Colors.border, borderWidth: 1, borderRadius: 14, padding: 14 },
  senderWarn: { borderColor: Colors.riskHigh, borderWidth: 1 },
  cardText: { color: Colors.textSecondary, fontSize: 12.5, lineHeight: 18 },
  setupRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    backgroundColor: Colors.surface,
    borderColor: Colors.border,
    borderWidth: 1,
    borderRadius: 14,
    padding: 12,
  },
  setupIcon: { fontSize: 18 },
  setupTitle: { color: Colors.textPrimary, fontSize: 13, fontWeight: '800' },
  setupDesc: { color: Colors.textSecondary, fontSize: 11, lineHeight: 15, marginTop: 2 },
  setupBtn: { backgroundColor: Colors.primary, borderRadius: 10, paddingHorizontal: 12, paddingVertical: 8 },
  setupBtnText: { color: Colors.white, fontSize: 12, fontWeight: '800' },
  testBtn: {
    borderWidth: 1,
    borderStyle: 'dashed',
    borderColor: Colors.primaryLight,
    borderRadius: 12,
    padding: 12,
    alignItems: 'center',
  },
  testText: { color: Colors.primaryLight, fontSize: 12.5, fontWeight: '800' },
  listHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  clearText: { color: Colors.riskHigh, fontSize: 12, fontWeight: '700', marginTop: 6 },
  alertRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    backgroundColor: Colors.surface,
    borderColor: Colors.border,
    borderWidth: 1,
    borderRadius: 14,
    padding: 12,
  },
  levelDot: { width: 10, height: 10, borderRadius: 5 },
  alertTitle: { color: Colors.textPrimary, fontSize: 13, fontWeight: '800' },
  alertExcerpt: { color: Colors.textSecondary, fontSize: 11.5, lineHeight: 16, marginTop: 2 },
  alertMeta: { color: Colors.textMuted, fontSize: 10, marginTop: 4 },
  chev: { color: Colors.textMuted, fontSize: 22 },
  footnote: { color: Colors.textMuted, fontSize: 10, lineHeight: 14, textAlign: 'center', marginTop: 10 },
  back: { paddingVertical: 4 },
  backText: { color: Colors.primaryLight, fontSize: 13, fontWeight: '700' },
  msgBox: { backgroundColor: Colors.surface, borderColor: Colors.border, borderWidth: 1, borderRadius: 14, padding: 12 },
  msgMeta: { color: Colors.textMuted, fontSize: 10.5, marginBottom: 6 },
  msgText: { color: Colors.textPrimary, fontSize: 13, lineHeight: 19 },
  deleteBtn: { alignItems: 'center', padding: 12 },
  deleteText: { color: Colors.riskHigh, fontSize: 12, fontWeight: '700' },
});
