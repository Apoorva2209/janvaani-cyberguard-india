import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity, Linking, Share, Alert } from 'react-native';
import { Colors } from '../theme/colors';
import { buildComplaintDraft, ComplaintInput, OFFICIAL_LINKS } from '../services/complaintKit';

/**
 * One-tap reporting kit. Opens official channels; the citizen files the
 * complaint themselves (JanVaani never submits on their behalf).
 */
export const ReportPanel: React.FC<{ input: ComplaintInput }> = ({ input }) => {
  const draft = buildComplaintDraft(input);

  const open = (url: string) =>
    Linking.openURL(url).catch(() => Alert.alert('Could not open', url));

  const shareDraft = () =>
    Share.share({ title: 'Cyber fraud complaint details', message: draft }).catch(() => undefined);

  return (
    <View style={styles.card}>
      <Text style={styles.heading}>🚨 Report this</Text>
      <Text style={styles.sub}>
        We've prepared your complaint details. Copy or share them, then submit on the official portal.
        JanVaani does not file complaints for you — only you can, with your own login.
      </Text>

      <TouchableOpacity style={[styles.btn, styles.btnDanger]} onPress={() => open(OFFICIAL_LINKS.helpline)}>
        <Text style={styles.btnText}>📞 Lost money? Call 1930 now</Text>
      </TouchableOpacity>
      <TouchableOpacity style={[styles.btn, styles.btnPrimary]} onPress={shareDraft}>
        <Text style={styles.btnText}>📋 Copy / share complaint draft</Text>
      </TouchableOpacity>
      <TouchableOpacity style={styles.btn} onPress={() => open(OFFICIAL_LINKS.cybercrimePortal)}>
        <Text style={styles.btnText}>🏛️ File on cybercrime.gov.in ↗</Text>
      </TouchableOpacity>
      <TouchableOpacity style={styles.btn} onPress={() => open(OFFICIAL_LINKS.chakshu)}>
        <Text style={styles.btnText}>📵 Report fraud SMS/call on Sanchar Saathi (Chakshu) ↗</Text>
      </TouchableOpacity>

      <Text style={styles.previewLabel}>Draft preview</Text>
      <Text style={styles.preview} selectable numberOfLines={14}>
        {draft}
      </Text>
    </View>
  );
};

const styles = StyleSheet.create({
  card: {
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.riskHighBorder,
    borderRadius: 16,
    padding: 16,
    gap: 8,
    marginTop: 12,
  },
  heading: { color: Colors.textPrimary, fontSize: 16, fontWeight: '900' },
  sub: { color: Colors.textSecondary, fontSize: 11.5, lineHeight: 16, marginBottom: 4 },
  btn: {
    backgroundColor: Colors.surfaceLight,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 12,
    paddingVertical: 12,
    paddingHorizontal: 14,
  },
  btnDanger: { backgroundColor: Colors.riskHigh, borderColor: Colors.riskHigh },
  btnPrimary: { backgroundColor: Colors.primary, borderColor: Colors.primary },
  btnText: { color: Colors.white, fontSize: 13, fontWeight: '800' },
  previewLabel: { color: Colors.textMuted, fontSize: 10.5, fontWeight: '700', marginTop: 6 },
  preview: {
    color: Colors.textSecondary,
    fontSize: 10.5,
    lineHeight: 15,
    fontFamily: 'monospace',
    backgroundColor: Colors.background,
    borderRadius: 10,
    padding: 10,
  },
});
