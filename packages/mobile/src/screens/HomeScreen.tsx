import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
} from 'react-native';
import { Colors } from '../theme/colors';
import { CheckerModality } from '../types';
import { useTranslations } from '../localization/i18n';
import { EmergencyBanner } from '../components/EmergencyBanner';

interface HomeScreenProps {
  onSelectModality: (modality: CheckerModality) => void;
  onNavigateToLearn: () => void;
}

export const HomeScreen: React.FC<HomeScreenProps> = ({
  onSelectModality,
  onNavigateToLearn,
}) => {
  const { t } = useTranslations();

  const actions = [
    {
      id: 'message' as CheckerModality,
      icon: '💬',
      title: t.home.actionSms,
      desc: t.home.actionSmsDesc,
      tag: 'Text / SMS / WhatsApp',
    },
    {
      id: 'call' as CheckerModality,
      icon: '📞',
      title: t.home.actionCall,
      desc: t.home.actionCallDesc,
      tag: 'Phone Calls & Scripts',
    },
    {
      id: 'link' as CheckerModality,
      icon: '🔗',
      title: t.home.actionLink,
      desc: t.home.actionLinkDesc,
      tag: 'URLs & Payment QR',
    },
    {
      id: 'media' as CheckerModality,
      icon: '🖼️',
      title: t.home.actionMedia,
      desc: t.home.actionMediaDesc,
      tag: 'Photo / Video / Deepfake',
    },
    {
      id: 'audio' as CheckerModality,
      icon: '🎙️',
      title: t.home.actionAudio,
      desc: t.home.actionAudioDesc,
      tag: 'Audio & Voice Clones',
    },
  ];

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Golden Hour Emergency Notification */}
      <EmergencyBanner />

      {/* Primary Intake Question */}
      <View style={styles.heroSection}>
        <Text style={styles.heroHeading}>{t.home.heading}</Text>
        <Text style={styles.heroSubheading}>{t.home.subheading}</Text>
      </View>

      {/* 5 Core Action Cards */}
      <View style={styles.actionsList}>
        {actions.map((act) => (
          <TouchableOpacity
            key={act.id}
            style={styles.actionCard}
            onPress={() => onSelectModality(act.id)}
            accessibilityRole="button"
            accessibilityLabel={`${act.title}. ${act.desc}`}
          >
            <View style={styles.cardIconBox}>
              <Text style={styles.cardIcon}>{act.icon}</Text>
            </View>

            <View style={styles.cardContent}>
              <View style={styles.cardHeaderRow}>
                <Text style={styles.cardTitle}>{act.title}</Text>
                <Text style={styles.arrowIcon}>➔</Text>
              </View>
              <Text style={styles.cardDesc}>{act.desc}</Text>
              <View style={styles.cardTagBox}>
                <Text style={styles.cardTagText}>{act.tag}</Text>
              </View>
            </View>
          </TouchableOpacity>
        ))}
      </View>

      {/* Skilling & Habits Spotlight Card (Inspired by MY Bharat & Skill India) */}
      <View style={styles.habitsSpotlightCard}>
        <View style={styles.habitsTopRow}>
          <View style={styles.habitsBadge}>
            <Text style={styles.habitsBadgeText}>💡 Skilling & Awareness</Text>
          </View>
          <Text style={styles.habitsDuration}>2 min lesson</Text>
        </View>

        <Text style={styles.habitsTitle}>
          The Golden Rule: Never Enter UPI PIN to Receive Money
        </Text>
        <Text style={styles.habitsDesc}>
          Did you know? Over 60% of lottery and cashback scams exploit confusion about how UPI collect requests work. Test your reflexes in our quick quiz.
        </Text>

        <TouchableOpacity style={styles.habitsButton} onPress={onNavigateToLearn}>
          <Text style={styles.habitsButtonText}>Take Quick Quiz ➔</Text>
        </TouchableOpacity>
      </View>

      {/* Independent Prototype Clarification */}
      <View style={styles.footerNotice}>
        <Text style={styles.footerNoticeText}>
          {t.app.disclaimerBanner}
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
  heroSection: {
    paddingHorizontal: 16,
    paddingTop: 8,
    paddingBottom: 12,
  },
  heroHeading: {
    color: Colors.textPrimary,
    fontSize: 22,
    fontWeight: '900',
    letterSpacing: -0.4,
  },
  heroSubheading: {
    color: Colors.textSecondary,
    fontSize: 12.5,
    marginTop: 4,
    lineHeight: 18,
  },
  actionsList: {
    paddingHorizontal: 16,
    gap: 10,
  },
  actionCard: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 16,
    padding: 14,
    gap: 12,
  },
  cardIconBox: {
    width: 48,
    height: 48,
    borderRadius: 14,
    backgroundColor: Colors.surfaceLight,
    borderWidth: 1,
    borderColor: Colors.border,
    alignItems: 'center',
    justifyContent: 'center',
  },
  cardIcon: {
    fontSize: 24,
  },
  cardContent: {
    flex: 1,
  },
  cardHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  cardTitle: {
    color: Colors.textPrimary,
    fontSize: 14,
    fontWeight: '800',
  },
  arrowIcon: {
    color: Colors.primaryLight,
    fontSize: 14,
    fontWeight: '800',
  },
  cardDesc: {
    color: Colors.textSecondary,
    fontSize: 11,
    marginTop: 2,
    lineHeight: 15,
  },
  cardTagBox: {
    alignSelf: 'flex-start',
    backgroundColor: 'rgba(255, 255, 255, 0.05)',
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
    marginTop: 6,
  },
  cardTagText: {
    color: '#93C5FD',
    fontSize: 9.5,
    fontWeight: '600',
  },
  habitsSpotlightCard: {
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 16,
    padding: 16,
    marginHorizontal: 16,
    marginTop: 16,
  },
  habitsTopRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  habitsBadge: {
    backgroundColor: 'rgba(249, 115, 22, 0.15)',
    borderWidth: 1,
    borderColor: 'rgba(249, 115, 22, 0.3)',
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
  },
  habitsBadgeText: {
    color: '#FB923C',
    fontSize: 10,
    fontWeight: '700',
  },
  habitsDuration: {
    color: Colors.textSecondary,
    fontSize: 10.5,
  },
  habitsTitle: {
    color: Colors.textPrimary,
    fontSize: 14,
    fontWeight: '800',
  },
  habitsDesc: {
    color: Colors.textSecondary,
    fontSize: 11.5,
    marginTop: 4,
    lineHeight: 16,
  },
  habitsButton: {
    alignSelf: 'flex-start',
    backgroundColor: Colors.primary,
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 8,
    marginTop: 12,
  },
  habitsButtonText: {
    color: Colors.white,
    fontSize: 11.5,
    fontWeight: '700',
  },
  footerNotice: {
    paddingHorizontal: 20,
    marginTop: 20,
  },
  footerNoticeText: {
    color: Colors.textMuted,
    fontSize: 10,
    textAlign: 'center',
    lineHeight: 14,
  },
});
