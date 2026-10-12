import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet, Linking, Platform } from 'react-native';
import { Colors } from '../theme/colors';
import { getCurrentLanguageInfo, useTranslations } from '../localization/i18n';

interface HeaderProps {
  onOpenLanguageModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenLanguageModal }) => {
  const { t, langInfo, isFallback } = useTranslations();

  const handleCall1930 = () => {
    Linking.openURL('tel:1930');
  };

  return (
    <View style={styles.container}>
      {/* Indian National Tricolor Accent Bar */}
      <View style={styles.tricolorBar}>
        <View style={[styles.tricolorSegment, { backgroundColor: '#FF9933' }]} />
        <View style={[styles.tricolorSegment, { backgroundColor: '#FFFFFF' }]} />
        <View style={[styles.tricolorSegment, { backgroundColor: '#128807' }]} />
      </View>

      {/* Main Header Row */}
      <View style={styles.mainRow}>
        <View style={styles.brandContainer}>
          <View style={styles.logoBadge}>
            <Text style={styles.logoText}>🛡️</Text>
          </View>
          <View>
            <View style={styles.titleRow}>
              <Text style={styles.brandTitle}>JanVaani</Text>
              <View style={styles.prototypePill}>
                <Text style={styles.prototypeText}>Prototype</Text>
              </View>
            </View>
            <Text style={styles.brandSubtitle}>जनवाणी • Citizen Cyber Shield</Text>
          </View>
        </View>

        {/* Action Controls */}
        <View style={styles.actionsRow}>
          {/* Language Selector Button */}
          <TouchableOpacity
            style={styles.langButton}
            onPress={onOpenLanguageModal}
            accessibilityLabel={`Change language, currently set to ${langInfo.name}`}
            accessibilityRole="button"
          >
            <Text style={styles.langIcon}>🌐</Text>
            <Text style={styles.langName} numberOfLines={1}>
              {langInfo.nativeName}
            </Text>
          </TouchableOpacity>

          {/* Emergency 1930 Dial Button */}
          <TouchableOpacity
            style={styles.emergencyButton}
            onPress={handleCall1930}
            accessibilityLabel="Call national cyber financial fraud helpline 1930"
            accessibilityRole="button"
          >
            <Text style={styles.emergencyIcon}>📞</Text>
            <Text style={styles.emergencyText}>1930</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Fallback Warning Notice when an unreviewed language is active */}
      {isFallback && (
        <View style={styles.fallbackNotice}>
          <Text style={styles.fallbackText}>
            ℹ️ {langInfo.name} ({langInfo.nativeName}) localization is utilizing English fallback state. Human review is pending.
          </Text>
        </View>
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    backgroundColor: Colors.surface,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
    paddingTop: Platform.OS === 'ios' ? 48 : 36,
  },
  tricolorBar: {
    flexDirection: 'row',
    height: 3,
    width: '100%',
  },
  tricolorSegment: {
    flex: 1,
    height: '100%',
  },
  mainRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingVertical: 12,
  },
  brandContainer: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  logoBadge: {
    width: 38,
    height: 38,
    borderRadius: 10,
    backgroundColor: Colors.surfaceLight,
    borderWidth: 1,
    borderColor: Colors.border,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 10,
  },
  logoText: {
    fontSize: 20,
  },
  titleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  brandTitle: {
    color: Colors.textPrimary,
    fontSize: 17,
    fontWeight: '800',
    letterSpacing: -0.3,
  },
  prototypePill: {
    backgroundColor: 'rgba(99, 102, 241, 0.15)',
    paddingHorizontal: 6,
    paddingVertical: 1,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: 'rgba(99, 102, 241, 0.3)',
  },
  prototypeText: {
    color: Colors.primaryLight,
    fontSize: 10,
    fontWeight: '700',
    textTransform: 'uppercase',
  },
  brandSubtitle: {
    color: Colors.textSecondary,
    fontSize: 11,
    marginTop: 1,
  },
  actionsRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  langButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: Colors.surfaceLight,
    borderWidth: 1,
    borderColor: Colors.border,
    paddingHorizontal: 8,
    paddingVertical: 6,
    borderRadius: 8,
    gap: 4,
  },
  langIcon: {
    fontSize: 12,
  },
  langName: {
    color: Colors.textPrimary,
    fontSize: 11,
    fontWeight: '600',
    maxWidth: 60,
  },
  emergencyButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#DC2626',
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 8,
    gap: 4,
  },
  emergencyIcon: {
    fontSize: 11,
  },
  emergencyText: {
    color: Colors.white,
    fontSize: 12,
    fontWeight: '800',
  },
  fallbackNotice: {
    backgroundColor: 'rgba(245, 158, 11, 0.15)',
    borderTopWidth: 1,
    borderTopColor: 'rgba(245, 158, 11, 0.3)',
    paddingHorizontal: 16,
    paddingVertical: 4,
  },
  fallbackText: {
    color: '#FCD34D',
    fontSize: 10,
    fontWeight: '600',
  },
});
