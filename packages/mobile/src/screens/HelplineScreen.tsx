import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Linking,
} from 'react-native';
import { Colors } from '../theme/colors';

export const HelplineScreen: React.FC = () => {
  const handleDial1930 = () => {
    Linking.openURL('tel:1930');
  };

  const handleOpenCybercrime = () => {
    Linking.openURL('https://cybercrime.gov.in');
  };

  const handleOpenSancharSaathi = () => {
    Linking.openURL('https://sancharsaathi.gov.in');
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Header Banner */}
      <View style={styles.headerBlock}>
        <Text style={styles.headerTitle}>National Cybercrime Assistance</Text>
        <Text style={styles.headerSubtitle}>
          Official channels to report financial fraud, block stolen handsets, and report spam telecom numbers.
        </Text>
      </View>

      {/* Primary Emergency Card (1930) */}
      <View style={styles.primaryEmergencyCard}>
        <View style={styles.badgeRow}>
          <Text style={styles.badgeText}>24x7 Citizen Helpline</Text>
        </View>
        <Text style={styles.cardBigTitle}>1930</Text>
        <Text style={styles.cardServiceTitle}>
          Citizen Financial Cyber Fraud Reporting Management System (CFCFRMS)
        </Text>
        <Text style={styles.cardDesc}>
          Operated by the Ministry of Home Affairs (MHA) Indian Cybercrime Coordination Centre (I4C). Direct integration with major public & private banks to freeze siphoned funds.
        </Text>

        <TouchableOpacity style={styles.dialBigBtn} onPress={handleDial1930}>
          <Text style={styles.dialBigBtnText}>📞 Dial 1930 Now (Toll Free)</Text>
        </TouchableOpacity>
      </View>

      {/* Official Government Portals */}
      <View style={styles.portalsSection}>
        <Text style={styles.sectionTitle}>Official Indian Cyber Portals</Text>

        {/* Cybercrime Portal */}
        <TouchableOpacity style={styles.portalCard} onPress={handleOpenCybercrime}>
          <View style={styles.portalLeft}>
            <Text style={styles.portalIcon}>🏛️</Text>
            <View>
              <Text style={styles.portalName}>cybercrime.gov.in</Text>
              <Text style={styles.portalDesc}>
                National Cyber Crime Reporting Portal for formal complaints, women & child safety, and financial fraud tracking.
              </Text>
            </View>
          </View>
          <Text style={styles.portalLinkArrow}>↗</Text>
        </TouchableOpacity>

        {/* Sanchar Saathi */}
        <TouchableOpacity style={styles.portalCard} onPress={handleOpenSancharSaathi}>
          <View style={styles.portalLeft}>
            <Text style={styles.portalIcon}>📱</Text>
            <View>
              <Text style={styles.portalName}>sancharsaathi.gov.in</Text>
              <Text style={styles.portalDesc}>
                Department of Telecommunications (DoT): Chakshu facility to report fraudulent calls/SMS & CEIR to block lost handsets.
              </Text>
            </View>
          </View>
          <Text style={styles.portalLinkArrow}>↗</Text>
        </TouchableOpacity>
      </View>

      {/* 2-Hour Golden Hour Protocol Checklist */}
      <View style={styles.checklistCard}>
        <Text style={styles.checklistTitle}>
          ⏱️ Golden Hour Protocol: What to Do Immediately
        </Text>
        <View style={styles.checklistSteps}>
          <View style={styles.stepRow}>
            <Text style={styles.stepNum}>1.</Text>
            <Text style={styles.stepText}>
              <Text style={styles.bold}>Record Transaction UTR:</Text> Keep the 12-digit reference number from your bank debit SMS.
            </Text>
          </View>

          <View style={styles.stepRow}>
            <Text style={styles.stepNum}>2.</Text>
            <Text style={styles.stepText}>
              <Text style={styles.bold}>Call 1930 Immediately:</Text> Report within 2 hours. Police will issue automated lien alerts to destination bank accounts.
            </Text>
          </View>

          <View style={styles.stepRow}>
            <Text style={styles.stepNum}>3.</Text>
            <Text style={styles.stepText}>
              <Text style={styles.bold}>Freeze Bank Accounts:</Text> Use NetBanking or call your bank's dedicated helpline to block debit cards and UPI transactions.
            </Text>
          </View>

          <View style={styles.stepRow}>
            <Text style={styles.stepNum}>4.</Text>
            <Text style={styles.stepText}>
              <Text style={styles.bold}>Lodge Complaint Online:</Text> Complete formal registration on cybercrime.gov.in to obtain an acknowledgment number for court or bank claims.
            </Text>
          </View>
        </View>
      </View>

      {/* Disclaimer */}
      <View style={styles.disclaimerBlock}>
        <Text style={styles.disclaimerText}>
          JanVaani provides informational and educational guidance. JanVaani is not an investigative or police authority and does not file official complaints.
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
  primaryEmergencyCard: {
    backgroundColor: '#380B0B',
    borderWidth: 1.5,
    borderColor: '#7F1D1D',
    borderRadius: 18,
    padding: 18,
    marginHorizontal: 16,
    marginTop: 10,
  },
  badgeRow: {
    alignSelf: 'flex-start',
    backgroundColor: 'rgba(239, 68, 68, 0.2)',
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
    marginBottom: 6,
  },
  badgeText: {
    color: '#F87171',
    fontSize: 10,
    fontWeight: '800',
    textTransform: 'uppercase',
  },
  cardBigTitle: {
    color: Colors.white,
    fontSize: 36,
    fontWeight: '900',
    letterSpacing: -1,
  },
  cardServiceTitle: {
    color: '#FECACA',
    fontSize: 13,
    fontWeight: '800',
    marginTop: 2,
  },
  cardDesc: {
    color: '#FCA5A5',
    fontSize: 11.5,
    marginTop: 6,
    lineHeight: 16,
  },
  dialBigBtn: {
    backgroundColor: '#DC2626',
    borderRadius: 12,
    paddingVertical: 12,
    alignItems: 'center',
    marginTop: 14,
  },
  dialBigBtnText: {
    color: Colors.white,
    fontSize: 13.5,
    fontWeight: '800',
  },
  portalsSection: {
    paddingHorizontal: 16,
    marginTop: 18,
    gap: 8,
  },
  sectionTitle: {
    color: Colors.textPrimary,
    fontSize: 13,
    fontWeight: '800',
    marginBottom: 4,
  },
  portalCard: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 14,
    padding: 14,
  },
  portalLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    flex: 1,
  },
  portalIcon: {
    fontSize: 22,
  },
  portalName: {
    color: '#93C5FD',
    fontSize: 13,
    fontWeight: '800',
  },
  portalDesc: {
    color: Colors.textSecondary,
    fontSize: 10.5,
    marginTop: 2,
    lineHeight: 14,
    paddingRight: 8,
  },
  portalLinkArrow: {
    color: Colors.primaryLight,
    fontSize: 16,
    fontWeight: '800',
  },
  checklistCard: {
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 16,
    padding: 16,
    marginHorizontal: 16,
    marginTop: 16,
  },
  checklistTitle: {
    color: Colors.textPrimary,
    fontSize: 13,
    fontWeight: '800',
    marginBottom: 10,
  },
  checklistSteps: {
    gap: 10,
  },
  stepRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 8,
  },
  stepNum: {
    color: Colors.primaryLight,
    fontSize: 12,
    fontWeight: '800',
    width: 14,
  },
  stepText: {
    flex: 1,
    color: Colors.textSecondary,
    fontSize: 11.5,
    lineHeight: 16,
  },
  bold: {
    color: Colors.textPrimary,
    fontWeight: '700',
  },
  disclaimerBlock: {
    paddingHorizontal: 20,
    marginTop: 20,
  },
  disclaimerText: {
    color: Colors.textMuted,
    fontSize: 10,
    textAlign: 'center',
    lineHeight: 14,
  },
});
