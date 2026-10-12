import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
} from 'react-native';
import { Colors } from '../theme/colors';
import { SAFE_HABITS_LESSONS } from '../services/lessonsData';
import { useTranslations } from '../localization/i18n';
import { SafeHabitsLesson } from '../types';

export const LearnScreen: React.FC = () => {
  const { t } = useTranslations();
  const [selectedLesson, setSelectedLesson] = useState<SafeHabitsLesson | null>(
    SAFE_HABITS_LESSONS[0] || null
  );
  const [selectedOptionIndex, setSelectedOptionIndex] = useState<number | null>(
    null
  );
  const [showExplanation, setShowExplanation] = useState<boolean>(false);

  const handleOptionSelect = (index: number) => {
    setSelectedOptionIndex(index);
    setShowExplanation(true);
  };

  const handleLessonSwitch = (lesson: SafeHabitsLesson) => {
    setSelectedLesson(lesson);
    setSelectedOptionIndex(null);
    setShowExplanation(false);
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Header Banner */}
      <View style={styles.headerBlock}>
        <View style={styles.badgeRow}>
          <Text style={styles.badgeText}>Skill India & MY Bharat Inspired</Text>
        </View>
        <Text style={styles.headerTitle}>{t.learn.title}</Text>
        <Text style={styles.headerSubtitle}>{t.learn.subtitle}</Text>
      </View>

      {/* Lesson Selector Chips */}
      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        contentContainerStyle={styles.lessonsChipRow}
      >
        {SAFE_HABITS_LESSONS.map((l) => {
          const isSelected = selectedLesson?.id === l.id;
          return (
            <TouchableOpacity
              key={l.id}
              style={[
                styles.lessonChip,
                isSelected && styles.lessonChipSelected,
              ]}
              onPress={() => handleLessonSwitch(l)}
            >
              <Text
                style={[
                  styles.lessonChipText,
                  isSelected && styles.lessonChipTextSelected,
                ]}
                numberOfLines={1}
              >
                {l.title}
              </Text>
            </TouchableOpacity>
          );
        })}
      </ScrollView>

      {/* Active Lesson Card */}
      {selectedLesson && (
        <View style={styles.lessonCard}>
          <View style={styles.cardHeader}>
            <Text style={styles.lessonCategory}>
              {selectedLesson.category.toUpperCase()} • {selectedLesson.durationMin} MIN SKILL
            </Text>
            <Text style={styles.lessonMainTitle}>{selectedLesson.title}</Text>
            <Text style={styles.lessonNativeTitle}>{selectedLesson.nativeTitle}</Text>
          </View>

          <Text style={styles.lessonSummary}>{selectedLesson.summary}</Text>

          {/* Key Takeaways Checklist */}
          <View style={styles.takeawaysBox}>
            <Text style={styles.takeawaysHeading}>Key Digital Habits:</Text>
            {selectedLesson.takeaways.map((point, idx) => (
              <View key={idx} style={styles.takeawayItem}>
                <Text style={styles.takeawayBullet}>✓</Text>
                <Text style={styles.takeawayText}>{point}</Text>
              </View>
            ))}
          </View>

          {/* Interactive Quiz Reflex Module */}
          <View style={styles.quizSection}>
            <Text style={styles.quizPrompt}>{t.learn.quizPrompt}</Text>
            <Text style={styles.quizQuestion}>
              {selectedLesson.quiz.question}
            </Text>

            <View style={styles.optionsList}>
              {selectedLesson.quiz.options.map((opt, oIdx) => {
                const isSelected = selectedOptionIndex === oIdx;
                const isCorrect = opt.isCorrect;

                let optStyle = styles.optionItem;
                if (showExplanation && isSelected) {
                  optStyle = isCorrect
                    ? styles.optionCorrect
                    : styles.optionIncorrect;
                }

                return (
                  <TouchableOpacity
                    key={oIdx}
                    style={optStyle}
                    onPress={() => handleOptionSelect(oIdx)}
                    disabled={showExplanation}
                  >
                    <Text style={styles.optionText}>{opt.text}</Text>
                  </TouchableOpacity>
                );
              })}
            </View>

            {/* Explanation Display */}
            {showExplanation && selectedOptionIndex !== null && (
              <View
                style={[
                  styles.feedbackBox,
                  selectedLesson.quiz.options[selectedOptionIndex]?.isCorrect
                    ? styles.feedbackCorrect
                    : styles.feedbackIncorrect,
                ]}
              >
                <Text style={styles.feedbackTitle}>
                  {selectedLesson.quiz.options[selectedOptionIndex]?.isCorrect
                    ? t.learn.correctText
                    : t.learn.incorrectText}
                </Text>
                <Text style={styles.feedbackDesc}>
                  {selectedLesson.quiz.options[selectedOptionIndex]?.explanation}
                </Text>
              </View>
            )}
          </View>
        </View>
      )}
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
    backgroundColor: 'rgba(249, 115, 22, 0.15)',
    borderWidth: 1,
    borderColor: 'rgba(249, 115, 22, 0.3)',
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
    marginBottom: 6,
  },
  badgeText: {
    color: '#FB923C',
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
  lessonsChipRow: {
    paddingHorizontal: 16,
    paddingVertical: 10,
    gap: 8,
  },
  lessonChip: {
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 10,
  },
  lessonChipSelected: {
    backgroundColor: Colors.primary,
    borderColor: Colors.primaryLight,
  },
  lessonChipText: {
    color: Colors.textSecondary,
    fontSize: 11,
    fontWeight: '600',
  },
  lessonChipTextSelected: {
    color: Colors.white,
    fontWeight: '700',
  },
  lessonCard: {
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 18,
    padding: 16,
    marginHorizontal: 16,
    marginTop: 4,
    gap: 14,
  },
  cardHeader: {
    gap: 2,
  },
  lessonCategory: {
    color: '#93C5FD',
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.5,
  },
  lessonMainTitle: {
    color: Colors.textPrimary,
    fontSize: 16,
    fontWeight: '800',
  },
  lessonNativeTitle: {
    color: Colors.textSecondary,
    fontSize: 12,
  },
  lessonSummary: {
    color: Colors.textPrimary,
    fontSize: 12.5,
    lineHeight: 18,
  },
  takeawaysBox: {
    backgroundColor: Colors.surfaceLight,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 12,
    padding: 12,
    gap: 6,
  },
  takeawaysHeading: {
    color: '#34D399',
    fontSize: 11.5,
    fontWeight: '700',
    marginBottom: 2,
  },
  takeawayItem: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 6,
  },
  takeawayBullet: {
    color: '#34D399',
    fontSize: 11,
    fontWeight: '800',
    marginTop: 1,
  },
  takeawayText: {
    flex: 1,
    color: Colors.textSecondary,
    fontSize: 11,
    lineHeight: 15,
  },
  quizSection: {
    borderTopWidth: 1,
    borderTopColor: Colors.border,
    paddingTop: 14,
    gap: 8,
  },
  quizPrompt: {
    color: '#FBBF24',
    fontSize: 11,
    fontWeight: '800',
    textTransform: 'uppercase',
  },
  quizQuestion: {
    color: Colors.textPrimary,
    fontSize: 13,
    fontWeight: '700',
    lineHeight: 18,
  },
  optionsList: {
    gap: 8,
    marginTop: 4,
  },
  optionItem: {
    backgroundColor: Colors.surfaceLight,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 10,
    padding: 12,
  },
  optionCorrect: {
    backgroundColor: 'rgba(16, 185, 129, 0.2)',
    borderWidth: 1.5,
    borderColor: '#10B981',
    borderRadius: 10,
    padding: 12,
  },
  optionIncorrect: {
    backgroundColor: 'rgba(239, 68, 68, 0.2)',
    borderWidth: 1.5,
    borderColor: '#EF4444',
    borderRadius: 10,
    padding: 12,
  },
  optionText: {
    color: Colors.textPrimary,
    fontSize: 11.5,
    lineHeight: 16,
  },
  feedbackBox: {
    borderRadius: 10,
    padding: 12,
    marginTop: 6,
    gap: 2,
  },
  feedbackCorrect: {
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    borderWidth: 1,
    borderColor: '#059669',
  },
  feedbackIncorrect: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    borderWidth: 1,
    borderColor: '#DC2626',
  },
  feedbackTitle: {
    fontSize: 12,
    fontWeight: '800',
    color: Colors.textPrimary,
  },
  feedbackDesc: {
    color: Colors.textSecondary,
    fontSize: 11,
    lineHeight: 15,
  },
});
