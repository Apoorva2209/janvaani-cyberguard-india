import React from 'react';
import { View, Text, StyleSheet, ScrollView } from 'react-native';
import { Colors } from '../theme/colors';
import { useTranslations } from '../localization/i18n';

export const PrivacyScreen: React.FC = () => {
  const { t } = useTranslations();

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Header Block */}
      <View style={styles.headerBlock}>
        <View style={styles.badgeRow}>
          <Text style={styles.badgeText}>DPDP Act 2023 Aligned</Text>
        </View>
        <Text style={styles.headerTitle}>{t.privacy.title}</Text>
        <Text style={styles.headerSubtitle}>
          Sovereign Indian data governance: Zero surveillance, zero citizen profiling, and short-lived retention.
        </Text>
      </View>

      {/* 3 Core Privacy Commitments */}
      <View style={styles.cardsList}>
        <View style={styles.principleCard}>
          <Text style={styles.principleIcon}>🚫</Text>
          <View style={styles.principleContent}>
            <Text style={styles.principleTitle}>{t.privacy.principle1Title}</Text>
            <Text style={styles.principleDesc}>{t.privacy.principle1Desc}</Text>
          </View>
        </View>

        <View style={styles.principleCard}>
          <Text style={styles.principleIcon}>⏱️</Text>
          <View style={styles.principleContent}>
            <Text style={styles.principleTitle}>{t.privacy.principle2Title}</Text>
            <Text style={styles.principleDesc}>{t.privacy.principle2Desc}</Text>
          </View>
        </View>

        <View style={styles.principleCard}>
          <Text style={styles.principleIcon}>🛡️</Text>
          <View style={styles.principleContent}>
            <Text style={styles.principleTitle}>{t.privacy.principle3Title}</Text>
            <Text style={styles.principleDesc}>{t.privacy.principle3Desc}</Text>
          </View>
        </View>
      </View>

      {/* Statutory Rights Section */}
      <View style={styles.rightsSection}>
        <Text style={styles.sectionTitle}>Your Statutory Rights under DPDP Act 2023</Text>
        <View style={styles.rightsBox}>
          <View style={styles.rightRow}>
            <Text style={styles.rightSec}>Section 11(1):</Text>
            <Text style={styles.rightText}>Right to access your report summary anytime.</Text>
          </View>
          <View style={styles.rightRow}>
            <Text style={styles.rightSec}>Section 11(2):</Text>
            <Text style={styles.rightText}>Right to correction of false-positive threat flags.</Text>
          </View>
          <View style={styles.rightRow}>
            <Text style={styles.rightSec}>Section 11(3):</Text>
            <Text style={styles.rightText}>Right to erasure: Permanent destruction of submitted text and artifacts upon request.</Text>
          </View>
          <View style={styles.rightRow}>
            <Text style={styles.rightSec}>Section 12:</Text>
            <Text style={styles.rightText}>Right to grievance redressal for data-related concerns.</Text>
          </View>
        </View>
      </View>

      {/* Model Training Notice */}
      <View style={styles.noticeCard}>
        <Text style={styles.noticeTitle}>AI & Model Safety Notice</Text>
        <Text style={styles.noticeText}>
          Citizen submissions are evaluated solely for risk triage and are NEVER used to train external commercial AI models without explicit, separate consent.
        </Text>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: Colors.background,
  },
  content: {
    paddingBottom: 40,
  },
  headerBlock: {
    paddingHorizontal: 16,
    paddingTop: 12,
    paddingBottom: 8,
  },
  badgeRow: {
    alignSelf: 'flex-start',
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.3)',
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
    marginBottom: 6,
  },
  badgeText: {
    color: '#34D399',
    fontSize: 10,
    fontWeight: '700',
  },
  headerTitle: {
    color: Colors.textPrimary,
    fontSize: 20,
    fontWeight: '900',
  },
  headerSubtitle: {
    color: Colors.textSecondary,
    fontSize: 12,
    marginTop: 2,
    lineHeight: 16,
  },
  cardsList: {
    paddingHorizontal: 16,
    marginTop: 10,
    gap: 10,
  },
  principleCard: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 14,
    padding: 14,
    gap: 12,
  },
  principleIcon: {
    fontSize: 22,
    marginTop: 2,
  },
  principleContent: {
    flex: 1,
  },
  principleTitle: {
    color: Colors.textPrimary,
    fontSize: 13,
    fontWeight: '800',
  },
  principleDesc: {
    color: Colors.textSecondary,
    fontSize: 11,
    marginTop: 2,
    lineHeight: 15,
  },
  rightsSection: {
    paddingHorizontal: 16,
    marginTop: 16,
  },
  sectionTitle: {
    color: Colors.textPrimary,
    fontSize: 13,
    fontWeight: '800',
    marginBottom: 8,
  },
  rightsBox: {
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 14,
    padding: 14,
    gap: 8,
  },
  rightRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 6,
  },
  rightSec: {
    color: Colors.primaryLight,
    fontSize: 11,
    fontWeight: '700',
    width: 80,
  },
  rightText: {
    flex: 1,
    color: Colors.textSecondary,
    fontSize: 11,
    lineHeight: 15,
  },
  noticeCard: {
    backgroundColor: Colors.surfaceLight,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 14,
    padding: 14,
    marginHorizontal: 16,
    marginTop: 16,
    gap: 4,
  },
  noticeTitle: {
    color: Colors.textPrimary,
    fontSize: 12,
    fontWeight: '700',
  },
  noticeText: {
    color: Colors.textSecondary,
    fontSize: 10.5,
    lineHeight: 15,
  },
});
