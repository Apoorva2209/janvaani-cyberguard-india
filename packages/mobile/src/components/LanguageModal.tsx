import React from 'react';
import {
  Modal,
  View,
  Text,
  TouchableOpacity,
  ScrollView,
  StyleSheet,
  SafeAreaView,
} from 'react-native';
import { Colors } from '../theme/colors';
import { INDIAN_LANGUAGES_REGISTRY } from '../localization/languages';
import { getCurrentLanguageCode, setAppLanguage } from '../localization/i18n';

interface LanguageModalProps {
  visible: boolean;
  onClose: () => void;
  onSelectLanguage: (code: string) => void;
}

export const LanguageModal: React.FC<LanguageModalProps> = ({
  visible,
  onClose,
  onSelectLanguage,
}) => {
  const activeCode = getCurrentLanguageCode();

  const handleSelect = (code: string) => {
    setAppLanguage(code);
    onSelectLanguage(code);
    onClose();
  };

  return (
    <Modal
      visible={visible}
      animationType="slide"
      transparent={true}
      onRequestClose={onClose}
    >
      <View style={styles.overlay}>
        <SafeAreaView style={styles.modalContent}>
          {/* Modal Header */}
          <View style={styles.headerRow}>
            <View>
              <Text style={styles.title}>Choose Language / भाषा चुनें</Text>
              <Text style={styles.subtitle}>
                22 Scheduled Languages of India • 22 आधिकारिक भाषाएं
              </Text>
            </View>
            <TouchableOpacity onPress={onClose} style={styles.closeButton}>
              <Text style={styles.closeText}>✕</Text>
            </TouchableOpacity>
          </View>

          {/* Languages List */}
          <ScrollView contentContainerStyle={styles.listContainer}>
            {INDIAN_LANGUAGES_REGISTRY.map((lang) => {
              const isSelected = lang.code === activeCode;
              return (
                <TouchableOpacity
                  key={lang.code}
                  style={[
                    styles.langItem,
                    isSelected && styles.langItemSelected,
                  ]}
                  onPress={() => handleSelect(lang.code)}
                  accessibilityRole="button"
                  accessibilityLabel={`${lang.name}, ${lang.nativeName}`}
                >
                  <View style={styles.langNameBlock}>
                    <Text
                      style={[
                        styles.nativeNameText,
                        isSelected && styles.selectedText,
                      ]}
                    >
                      {lang.nativeName}
                    </Text>
                    <Text style={styles.englishNameText}>{lang.name}</Text>
                  </View>

                  {/* Status Badge */}
                  <View style={styles.badgeContainer}>
                    {lang.isHumanReviewed ? (
                      <View style={styles.reviewedBadge}>
                        <Text style={styles.reviewedBadgeText}>
                          ✓ Reviewed
                        </Text>
                      </View>
                    ) : (
                      <View style={styles.fallbackBadge}>
                        <Text style={styles.fallbackBadgeText}>
                          EN Fallback
                        </Text>
                      </View>
                    )}
                  </View>
                </TouchableOpacity>
              );
            })}
          </ScrollView>

          {/* Modal Footer Note */}
          <View style={styles.footerNote}>
            <Text style={styles.footerNoteText}>
              Bhashini Sovereign AI Integration: Safety-critical emergency warnings are human-reviewed in English & Hindi. Regional models fallback gracefully to certified English advisories.
            </Text>
          </View>
        </SafeAreaView>
      </View>
    </Modal>
  );
};

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.75)',
    justifyContent: 'flex-end',
  },
  modalContent: {
    backgroundColor: Colors.surface,
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
    borderWidth: 1,
    borderColor: Colors.border,
    maxHeight: '85%',
  },
  headerRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingTop: 16,
    paddingBottom: 12,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
  },
  title: {
    fontSize: 16,
    fontWeight: '800',
    color: Colors.textPrimary,
  },
  subtitle: {
    fontSize: 11,
    color: Colors.textSecondary,
    marginTop: 2,
  },
  closeButton: {
    width: 32,
    height: 32,
    borderRadius: 16,
    backgroundColor: Colors.surfaceLight,
    alignItems: 'center',
    justifyContent: 'center',
  },
  closeText: {
    color: Colors.textSecondary,
    fontSize: 14,
    fontWeight: '700',
  },
  listContainer: {
    paddingHorizontal: 16,
    paddingVertical: 12,
    gap: 8,
  },
  langItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: Colors.surfaceLight,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 12,
  },
  langItemSelected: {
    borderColor: Colors.primaryLight,
    backgroundColor: 'rgba(79, 70, 229, 0.2)',
  },
  langNameBlock: {
    flexDirection: 'row',
    alignItems: 'baseline',
    gap: 8,
  },
  nativeNameText: {
    fontSize: 15,
    fontWeight: '700',
    color: Colors.textPrimary,
  },
  englishNameText: {
    fontSize: 12,
    color: Colors.textSecondary,
  },
  selectedText: {
    color: '#A5B4FC',
  },
  badgeContainer: {
    alignItems: 'flex-end',
  },
  reviewedBadge: {
    backgroundColor: 'rgba(16, 185, 129, 0.2)',
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.4)',
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 6,
  },
  reviewedBadgeText: {
    color: '#34D399',
    fontSize: 10,
    fontWeight: '700',
  },
  fallbackBadge: {
    backgroundColor: 'rgba(245, 158, 11, 0.15)',
    borderWidth: 1,
    borderColor: 'rgba(245, 158, 11, 0.3)',
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 6,
  },
  fallbackBadgeText: {
    color: '#FBBF24',
    fontSize: 10,
    fontWeight: '700',
  },
  footerNote: {
    paddingHorizontal: 20,
    paddingVertical: 10,
    borderTopWidth: 1,
    borderTopColor: Colors.border,
    backgroundColor: Colors.background,
  },
  footerNoteText: {
    color: Colors.textMuted,
    fontSize: 10,
    lineHeight: 14,
    textAlign: 'center',
  },
});
