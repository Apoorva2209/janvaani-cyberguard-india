import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet, Linking } from 'react-native';
import { Colors } from '../theme/colors';
import { useTranslations } from '../localization/i18n';

export const EmergencyBanner: React.FC = () => {
  const { t } = useTranslations();

  const handleCall = () => {
    Linking.openURL('tel:1930');
  };

  const handleOpenPortal = () => {
    Linking.openURL('https://cybercrime.gov.in');
  };

  return (
    <View style={styles.card}>
      <View style={styles.headerRow}>
        <View style={styles.iconCircle}>
          <Text style={styles.alertIcon}>🚨</Text>
        </View>
        <View style={styles.titleBlock}>
          <Text style={styles.title}>{t.emergency.title}</Text>
          <Text style={styles.subtitle}>{t.emergency.shortNote}</Text>
        </View>
      </View>

      <View style={styles.buttonsRow}>
        <TouchableOpacity
          style={styles.dialBtn}
          onPress={handleCall}
          accessibilityRole="button"
          accessibilityLabel="Dial 1930 National Cybercrime Helpline"
        >
          <Text style={styles.dialBtnText}>📞 {t.emergency.dialButton}</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.portalBtn}
          onPress={handleOpenPortal}
          accessibilityRole="button"
          accessibilityLabel="Open National Cybercrime Reporting Portal in browser"
        >
          <Text style={styles.portalBtnText}>🌐 {t.emergency.portalButton}</Text>
        </TouchableOpacity>
      </View>

      <Text style={styles.statutoryNotice}>
        * JanVaani is an informational assistance tool and does NOT file formal police FIRs. Formal complaints must be registered directly with the National Cyber Crime Portal.
      </Text>
    </View>
  );
};

const styles = StyleSheet.create({
  card: {
    backgroundColor: '#380B0B',
    borderWidth: 1,
    borderColor: '#7F1D1D',
    borderRadius: 16,
    padding: 14,
    marginHorizontal: 16,
    marginVertical: 10,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    marginBottom: 10,
  },
  iconCircle: {
    width: 34,
    height: 34,
    borderRadius: 17,
    backgroundColor: '#7F1D1D',
    alignItems: 'center',
    justifyContent: 'center',
  },
  alertIcon: {
    fontSize: 16,
  },
  titleBlock: {
    flex: 1,
  },
  title: {
    color: '#FECACA',
    fontSize: 13,
    fontWeight: '800',
  },
  subtitle: {
    color: '#F87171',
    fontSize: 11,
    marginTop: 2,
    lineHeight: 15,
  },
  buttonsRow: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 4,
  },
  dialBtn: {
    flex: 1,
    backgroundColor: '#DC2626',
    borderRadius: 10,
    paddingVertical: 10,
    alignItems: 'center',
    justifyContent: 'center',
  },
  dialBtnText: {
    color: Colors.white,
    fontSize: 12,
    fontWeight: '800',
  },
  portalBtn: {
    flex: 1,
    backgroundColor: 'rgba(255, 255, 255, 0.08)',
    borderWidth: 1,
    borderColor: '#991B1B',
    borderRadius: 10,
    paddingVertical: 10,
    alignItems: 'center',
    justifyContent: 'center',
  },
  portalBtnText: {
    color: '#FCA5A5',
    fontSize: 11,
    fontWeight: '700',
  },
  statutoryNotice: {
    color: '#F87171',
    fontSize: 9.5,
    marginTop: 8,
    lineHeight: 13,
    fontStyle: 'italic',
  },
});
