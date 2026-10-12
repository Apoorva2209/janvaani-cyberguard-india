import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Linking,
  Share,
} from 'react-native';
import { AnalysisOutcome, RiskLabel } from '../types';
import { Colors } from '../theme/colors';
import { useTranslations } from '../localization/i18n';

interface ResultCardProps {
  outcome: AnalysisOutcome;
  onReset: () => void;
}

export const ResultCard: React.FC<ResultCardProps> = ({ outcome, onReset }) => {
  const { t } = useTranslations();

  const getLabelTheme = (label: RiskLabel) => {
    switch (label) {
      case 'HIGH_RISK':
        return {
          title: t.labels.highRisk,
          bg: Colors.riskHighBg,
          border: Colors.riskHighBorder,
          text: Colors.riskHigh,
          icon: '🚨',
        };
      case 'CHECK_CAREFULLY':
        return {
          title: t.labels.checkCarefully,
          bg: Colors.riskMediumBg,
          border: Colors.riskMediumBorder,
          text: Colors.riskMedium,
          icon: '⚠️',
        };
      case 'OFFICIAL_MATCH':
        return {
          title: t.labels.officialMatch,
          bg: Colors.officialMatchBg,
          border: Colors.officialMatchBorder,
          text: Colors.officialMatch,
          icon: '🏛️',
        };
      case 'NEEDS_REVIEW':
        return {
          title: t.labels.needsReview,
          bg: Colors.needsReviewBg,
          border: Colors.needsReviewBorder,
          text: Colors.needsReview,
          icon: '🔍',
        };
      case 'NO_COMMON_INDICATORS':
      default:
        return {
          title: t.labels.noCommonIndicators,
          bg: Colors.riskLowBg,
          border: Colors.riskLowBorder,
          text: Colors.riskLow,
          icon: '🛡️',
        };
    }
  };

  const theme = getLabelTheme(outcome.label);

  const handleShare = async () => {
    try {
      await Share.share({
        message: `JanVaani Cyber Alert [${outcome.id}]:\nAssessment: ${theme.title} (${Math.round(outcome.confidenceScore * 100)}% confidence)\nKey Finding: ${outcome.plainLanguageSummary}\nSafety Advice: Never share OTPs or enter UPI PINs to receive money. For fraud assistance, call 1930.`,
      });
    } catch {
      // Ignored
    }
  };

  const handleOpenSource = (url: string) => {
    Linking.openURL(url);
  };

  return (
    <View style={styles.container}>
      {/* Primary Result Banner */}
      <View style={[styles.badgeBanner, { backgroundColor: theme.bg, borderColor: theme.border }]}>
        <View style={styles.badgeTopRow}>
          <View style={styles.badgeLeft}>
            <Text style={styles.badgeIcon}>{theme.icon}</Text>
            <Text style={[styles.badgeTitle, { color: theme.text }]}>
              {theme.title}
            </Text>
          </View>
          <Text style={styles.reportIdText}>#{outcome.id}</Text>
        </View>

        <Text style={styles.summaryText}>{outcome.plainLanguageSummary}</Text>

        <View style={styles.metaRow}>
          <Text style={styles.metaText}>
            Confidence: {Math.round(outcome.confidenceScore * 100)}% • Analyzed at {outcome.timestamp}
          </Text>
        </View>
      </View>

      {/* Identified Warning Clues */}
      {outcome.evidenceClues.length > 0 && (
        <View style={styles.sectionCard}>
          <Text style={styles.sectionHeader}>{t.results.evidenceHeader}</Text>
          <View style={styles.cluesList}>
            {outcome.evidenceClues.map((clue, idx) => (
              <View key={idx} style={styles.clueItem}>
                <View style={styles.clueTop}>
                  <Text style={styles.clueTactic}>⚠️ {clue.tactic}</Text>
                </View>
                {clue.quote && (
                  <Text style={styles.clueQuote}>{clue.quote}</Text>
                )}
                <Text style={styles.clueExplanation}>{clue.explanation}</Text>
              </View>
            ))}
          </View>
        </View>
      )}

      {/* Official Public Source Match */}
      {outcome.officialMatch && (
        <View style={styles.officialMatchCard}>
          <View style={styles.officialHeaderRow}>
            <Text style={styles.officialHeaderTitle}>
              🏛️ {t.results.officialMatchHeader}
            </Text>
            <TouchableOpacity onPress={() => handleOpenSource(outcome.officialMatch!.url)}>
              <Text style={styles.officialSourceLink}>Source ↗</Text>
            </TouchableOpacity>
          </View>
          <Text style={styles.agencyName}>
            {outcome.officialMatch.sourceName} (Retrieved: {outcome.officialMatch.retrievalTime})
          </Text>
          <Text style={styles.matchedPassage}>
            "{outcome.officialMatch.matchedPassage}"
          </Text>
        </View>
      )}

      {/* Recommended Safe Next Steps */}
      <View style={styles.nextStepsCard}>
        <Text style={styles.nextStepsHeader}>{t.results.nextStepsHeader}</Text>
        <View style={styles.stepsList}>
          <Text style={styles.stepItem}>{t.results.stepStop}</Text>
          <Text style={styles.stepItem}>{t.results.stepNoOtp}</Text>
          <Text style={styles.stepItem}>{t.results.stepOfficial}</Text>
          <Text style={styles.stepItem}>{t.results.stepPreserve}</Text>
          <Text style={styles.stepItem}>{t.results.stepReport}</Text>
        </View>
      </View>

      {/* Confidence Limitations & Disclaimer */}
      <View style={styles.disclaimerBox}>
        <Text style={styles.disclaimerText}>{t.results.confidenceNote}</Text>
        <Text style={styles.disclaimerTextSmall}>{outcome.disclaimer}</Text>
      </View>

      {/* Action Buttons */}
      <View style={styles.actionsRow}>
        <TouchableOpacity style={styles.shareBtn} onPress={handleShare}>
          <Text style={styles.shareBtnText}>📤 {t.results.shareSafe}</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.resetBtn} onPress={onReset}>
          <Text style={styles.resetBtnText}>🔄 {t.results.resetButton}</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    gap: 12,
  },
  badgeBanner: {
    borderRadius: 16,
    borderWidth: 1.5,
    padding: 16,
  },
  badgeTopRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  badgeLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  badgeIcon: {
    fontSize: 18,
  },
  badgeTitle: {
    fontSize: 15,
    fontWeight: '800',
    letterSpacing: -0.2,
  },
  reportIdText: {
    color: Colors.textSecondary,
    fontSize: 10,
    fontFamily: 'monospace',
  },
  summaryText: {
    color: Colors.textPrimary,
    fontSize: 13,
    lineHeight: 19,
    fontWeight: '500',
    marginBottom: 8,
  },
  metaRow: {
    borderTopWidth: 1,
    borderTopColor: 'rgba(255, 255, 255, 0.1)',
    paddingTop: 8,
  },
  metaText: {
    color: Colors.textSecondary,
    fontSize: 10,
  },
  sectionCard: {
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 16,
    padding: 16,
  },
  sectionHeader: {
    color: Colors.textPrimary,
    fontSize: 13,
    fontWeight: '700',
    marginBottom: 10,
  },
  cluesList: {
    gap: 8,
  },
  clueItem: {
    backgroundColor: Colors.surfaceLight,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: Colors.border,
    padding: 12,
  },
  clueTop: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 4,
  },
  clueTactic: {
    color: '#F87171',
    fontSize: 12,
    fontWeight: '700',
  },
  clueQuote: {
    color: '#FCD34D',
    fontSize: 11,
    fontFamily: 'monospace',
    backgroundColor: 'rgba(0, 0, 0, 0.25)',
    padding: 6,
    borderRadius: 6,
    marginVertical: 4,
  },
  clueExplanation: {
    color: Colors.textSecondary,
    fontSize: 11.5,
    lineHeight: 16,
    marginTop: 2,
  },
  officialMatchCard: {
    backgroundColor: '#032541',
    borderWidth: 1,
    borderColor: '#0284C7',
    borderRadius: 16,
    padding: 14,
  },
  officialHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  officialHeaderTitle: {
    color: '#38BDF8',
    fontSize: 12.5,
    fontWeight: '800',
  },
  officialSourceLink: {
    color: '#7DD3FC',
    fontSize: 11,
    fontWeight: '700',
    textDecorationLine: 'underline',
  },
  agencyName: {
    color: Colors.textSecondary,
    fontSize: 10,
    marginBottom: 6,
  },
  matchedPassage: {
    color: Colors.textPrimary,
    fontSize: 11.5,
    lineHeight: 16,
    fontStyle: 'italic',
  },
  nextStepsCard: {
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 16,
    padding: 16,
  },
  nextStepsHeader: {
    color: Colors.textPrimary,
    fontSize: 13,
    fontWeight: '700',
    marginBottom: 10,
  },
  stepsList: {
    gap: 8,
  },
  stepItem: {
    color: Colors.textPrimary,
    fontSize: 11.5,
    lineHeight: 16,
  },
  disclaimerBox: {
    backgroundColor: Colors.background,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 12,
    padding: 12,
    gap: 4,
  },
  disclaimerText: {
    color: Colors.textSecondary,
    fontSize: 10.5,
    lineHeight: 14,
  },
  disclaimerTextSmall: {
    color: Colors.textMuted,
    fontSize: 9.5,
    lineHeight: 13,
  },
  actionsRow: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 4,
  },
  shareBtn: {
    flex: 1,
    backgroundColor: Colors.surfaceLight,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 12,
    paddingVertical: 12,
    alignItems: 'center',
  },
  shareBtnText: {
    color: Colors.textPrimary,
    fontSize: 12,
    fontWeight: '700',
  },
  resetBtn: {
    flex: 1,
    backgroundColor: Colors.primary,
    borderRadius: 12,
    paddingVertical: 12,
    alignItems: 'center',
  },
  resetBtnText: {
    color: Colors.white,
    fontSize: 12,
    fontWeight: '700',
  },
});
