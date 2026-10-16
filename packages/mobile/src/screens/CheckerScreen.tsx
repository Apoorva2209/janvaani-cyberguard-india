import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  ScrollView,
  StyleSheet,
  Switch,
  ActivityIndicator,
} from 'react-native';
import { Colors } from '../theme/colors';
import { AnalysisOutcome, CheckerModality } from '../types';
import { useTranslations } from '../localization/i18n';
import { analyzeSuspiciousContent } from '../services/heuristicEngine';
import { ResultCard } from '../components/ResultCard';
import { ReportPanel } from '../components/ReportPanel';

interface CheckerScreenProps {
  initialModality: CheckerModality;
  initialContent?: string;
  onBack: () => void;
}

export const CheckerScreen: React.FC<CheckerScreenProps> = ({
  initialModality,
  initialContent,
  onBack,
}) => {
  const { t } = useTranslations();
  const [modality, setModality] = useState<CheckerModality>(initialModality);
  const [content, setContent] = useState<string>(initialContent ?? '');
  const [claimedSender, setClaimedSender] = useState<string>('');
  const [claimedNumber, setClaimedNumber] = useState<string>('');
  const [selectedState, setSelectedState] = useState<string>('');
  const [selectedDistrict, setSelectedDistrict] = useState<string>('');
  const [isAnonymous, setIsAnonymous] = useState<boolean>(true);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [outcome, setOutcome] = useState<AnalysisOutcome | null>(null);

  const getModalityTitle = (m: CheckerModality) => {
    switch (m) {
      case 'call':
        return t.home.actionCall;
      case 'link':
        return t.home.actionLink;
      case 'media':
        return t.home.actionMedia;
      case 'audio':
        return t.home.actionAudio;
      case 'message':
      default:
        return t.home.actionSms;
    }
  };

  const getPlaceholder = (m: CheckerModality) => {
    switch (m) {
      case 'call':
        return t.checker.inputPlaceholderCall;
      case 'link':
        return t.checker.inputPlaceholderLink;
      case 'media':
        return t.checker.inputPlaceholderMedia;
      case 'audio':
        return t.checker.inputPlaceholderAudio;
      case 'message':
      default:
        return t.checker.inputPlaceholderMessage;
    }
  };

  const handleRunAnalysis = async () => {
    if (!content.trim()) return;

    setIsAnalyzing(true);
    // Brief realistic processing pause
    setTimeout(() => {
      const res = analyzeSuspiciousContent({
        modality,
        content,
        claimedSender: claimedSender || undefined,
        claimedNumber: claimedNumber || undefined,
        isAnonymous,
      });
      setOutcome(res);
      setIsAnalyzing(false);
    }, 700);
  };

  const loadPreset = (presetText: string, claimedOrg?: string, phone?: string) => {
    setContent(presetText);
    if (claimedOrg) setClaimedSender(claimedOrg);
    if (phone) setClaimedNumber(phone);
    setOutcome(null);
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Top Bar with Back Button */}
      <View style={styles.topBar}>
        <TouchableOpacity onPress={onBack} style={styles.backBtn}>
          <Text style={styles.backBtnText}>← Back</Text>
        </TouchableOpacity>
        <Text style={styles.modalityHeaderTitle}>{getModalityTitle(modality)}</Text>
        <View style={{ width: 40 }} />
      </View>

      {/* When Results Are Available, Show ResultCard */}
      {outcome ? (
        <View style={styles.resultsContainer}>
          <ResultCard
            outcome={outcome}
            onReset={() => {
              setOutcome(null);
              setContent('');
            }}
          />
          {(outcome.label === 'HIGH_RISK' || outcome.label === 'CHECK_CAREFULLY') && (
            <ReportPanel
              input={{
                source: modality === 'call' ? 'Phone call' : modality === 'link' ? 'Link' : 'Message',
                sender: claimedNumber || claimedSender,
                messageText: content,
                outcome,
              }}
            />
          )}
        </View>
      ) : (
        /* Evaluation Intake Form */
        <View style={styles.formContainer}>
          {/* Strict Safety Notice (Never enter OTP / PIN / Aadhaar) */}
          <View style={styles.safetyBox}>
            <Text style={styles.safetyHeading}>{t.checker.safetyNotice}</Text>
            <Text style={styles.safetyText}>{t.checker.safetyNoticeDetail}</Text>
          </View>

          {/* Caller ID Spoofing Warning */}
          {modality === 'call' && (
            <View style={styles.warningBox}>
              <Text style={styles.warningText}>{t.checker.callerIdWarning}</Text>
            </View>
          )}

          {/* Deepfake / Synthetic Media Warning */}
          {(modality === 'media' || modality === 'audio') && (
            <View style={styles.warningBox}>
              <Text style={styles.warningText}>{t.checker.deepfakeNotice}</Text>
            </View>
          )}

          {/* Fictional Presets for Demonstration */}
          <View style={styles.presetsBlock}>
            <Text style={styles.presetsLabel}>{t.checker.tryPresets}</Text>
            <View style={styles.presetsRow}>
              {modality === 'call' && (
                <>
                  <TouchableOpacity
                    style={styles.presetChip}
                    onPress={() =>
                      loadPreset(
                        'CBI Officer Sharma calling from Crime Branch. You are under Digital Arrest for an intercepted narcotics parcel containing 140g MDMA. Join Skype call immediately.',
                        'CBI Crime Branch',
                        '+91 99887 76655'
                      )
                    }
                  >
                    <Text style={styles.presetChipText}>🚨 Digital Arrest Call</Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={styles.presetChip}
                    onPress={() =>
                      loadPreset(
                        'Hello, this is SBI credit card division. Your account is blocked due to unverified KYC. Download AnyDesk so I can help you verify your identity.',
                        'SBI Card Support',
                        '1800-FAKE-SBI'
                      )
                    }
                  >
                    <Text style={styles.presetChipText}>🔒 Fake Bank KYC & AnyDesk</Text>
                  </TouchableOpacity>
                </>
              )}

              {modality === 'message' && (
                <>
                  <TouchableOpacity
                    style={styles.presetChip}
                    onPress={() =>
                      loadPreset(
                        'Dear consumer, your electricity power supply will be disconnected tonight at 9.30 PM from electricity office. Immediately call our discom officer at 9876543210.',
                        'State Discom Office',
                        '+91 98765 43210'
                      )
                    }
                  >
                    <Text style={styles.presetChipText}>⚡ Power Cut Tonight</Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={styles.presetChip}
                    onPress={() =>
                      loadPreset(
                        'Diwali Dhamaka! You have won ₹25,000 cash prize from PhonePe. Scan QR code and enter your UPI PIN to receive the prize directly into bank.',
                        'PhonePe Rewards'
                      )
                    }
                  >
                    <Text style={styles.presetChipText}>💸 Lottery UPI PIN Trap</Text>
                  </TouchableOpacity>
                </>
              )}

              {modality === 'link' && (
                <TouchableOpacity
                  style={styles.presetChip}
                  onPress={() =>
                    loadPreset(
                      'https://sbi-kyc-pan-update-verification.com/login.php?customer_id=update'
                    )
                  }
                >
                  <Text style={styles.presetChipText}>🌐 Fake Bank Phishing URL</Text>
                </TouchableOpacity>
              )}

              {modality === 'media' && (
                <TouchableOpacity
                  style={styles.presetChip}
                  onPress={() =>
                    loadPreset(
                      'Screenshot of circular claiming Government is giving ₹5,000 monthly allowance under PM Yojna to all Aadhaar card holders.'
                    )
                  }
                >
                  <Text style={styles.presetChipText}>📰 Viral Fake Govt Circular</Text>
                </TouchableOpacity>
              )}

              {modality === 'audio' && (
                <TouchableOpacity
                  style={styles.presetChip}
                  onPress={() =>
                    loadPreset(
                      'Voice note claiming to be my cousin crying that they met with an accident and need ₹30,000 sent via UPI immediately.'
                    )
                  }
                >
                  <Text style={styles.presetChipText}>🎙️ Urgent Voice Clone Distress</Text>
                </TouchableOpacity>
              )}
            </View>
          </View>

          {/* Main Content Input */}
          <View style={styles.inputGroup}>
            <TextInput
              style={styles.textArea}
              value={content}
              onChangeText={setContent}
              placeholder={getPlaceholder(modality)}
              placeholderTextColor={Colors.textMuted}
              multiline
              numberOfLines={5}
              textAlignVertical="top"
              accessibilityLabel="Suspicious content input field"
            />
          </View>

          {/* Claimed Sender & Number (Optional) */}
          <View style={styles.optionalFieldsRow}>
            <View style={styles.fieldBox}>
              <Text style={styles.fieldLabel}>{t.checker.claimedSenderLabel}</Text>
              <TextInput
                style={styles.inputField}
                value={claimedSender}
                onChangeText={setClaimedSender}
                placeholder={t.checker.claimedSenderPlaceholder}
                placeholderTextColor={Colors.textMuted}
              />
            </View>

            <View style={styles.fieldBox}>
              <Text style={styles.fieldLabel}>{t.checker.claimedNumberLabel}</Text>
              <TextInput
                style={styles.inputField}
                value={claimedNumber}
                onChangeText={setClaimedNumber}
                placeholder={t.checker.claimedNumberPlaceholder}
                placeholderTextColor={Colors.textMuted}
                keyboardType="phone-pad"
              />
            </View>
          </View>

          {/* Optional District & State */}
          <View style={styles.optionalFieldsRow}>
            <View style={styles.fieldBox}>
              <Text style={styles.fieldLabel}>{t.checker.stateLabel}</Text>
              <TextInput
                style={styles.inputField}
                value={selectedState}
                onChangeText={setSelectedState}
                placeholder="e.g. Maharashtra, Uttar Pradesh"
                placeholderTextColor={Colors.textMuted}
              />
            </View>

            <View style={styles.fieldBox}>
              <Text style={styles.fieldLabel}>{t.checker.districtLabel}</Text>
              <TextInput
                style={styles.inputField}
                value={selectedDistrict}
                onChangeText={setSelectedDistrict}
                placeholder="e.g. Pune, Lucknow"
                placeholderTextColor={Colors.textMuted}
              />
            </View>
          </View>

          {/* Anonymous Report Switch */}
          <View style={styles.switchRow}>
            <Text style={styles.switchLabel}>{t.checker.anonymousOption}</Text>
            <Switch
              value={isAnonymous}
              onValueChange={setIsAnonymous}
              trackColor={{ false: Colors.border, true: Colors.primary }}
              thumbColor={Colors.white}
            />
          </View>

          {/* Submit Button */}
          <TouchableOpacity
            style={[
              styles.submitBtn,
              (!content.trim() || isAnalyzing) && styles.submitBtnDisabled,
            ]}
            onPress={handleRunAnalysis}
            disabled={!content.trim() || isAnalyzing}
            accessibilityRole="button"
            accessibilityLabel={t.checker.analyzeButton}
          >
            {isAnalyzing ? (
              <View style={styles.analyzingRow}>
                <ActivityIndicator color={Colors.white} size="small" />
                <Text style={styles.submitBtnText}>{t.checker.analyzing}</Text>
              </View>
            ) : (
              <Text style={styles.submitBtnText}>🛡️ {t.checker.analyzeButton}</Text>
            )}
          </TouchableOpacity>
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
  topBar: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
  },
  backBtn: {
    paddingVertical: 6,
    paddingHorizontal: 8,
  },
  backBtnText: {
    color: Colors.primaryLight,
    fontSize: 13,
    fontWeight: '700',
  },
  modalityHeaderTitle: {
    color: Colors.textPrimary,
    fontSize: 14,
    fontWeight: '800',
  },
  formContainer: {
    padding: 16,
    gap: 12,
  },
  resultsContainer: {
    padding: 16,
  },
  safetyBox: {
    backgroundColor: '#380B0B',
    borderWidth: 1,
    borderColor: '#7F1D1D',
    borderRadius: 12,
    padding: 12,
  },
  safetyHeading: {
    color: '#FECACA',
    fontSize: 12,
    fontWeight: '800',
    marginBottom: 2,
  },
  safetyText: {
    color: '#F87171',
    fontSize: 11,
    lineHeight: 15,
  },
  warningBox: {
    backgroundColor: 'rgba(245, 158, 11, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(245, 158, 11, 0.3)',
    borderRadius: 12,
    padding: 12,
  },
  warningText: {
    color: '#FCD34D',
    fontSize: 10.5,
    lineHeight: 15,
  },
  presetsBlock: {
    gap: 6,
  },
  presetsLabel: {
    color: Colors.textSecondary,
    fontSize: 11,
    fontWeight: '700',
  },
  presetsRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 6,
  },
  presetChip: {
    backgroundColor: Colors.surfaceLight,
    borderWidth: 1,
    borderColor: Colors.border,
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 8,
  },
  presetChipText: {
    color: Colors.textPrimary,
    fontSize: 11,
    fontWeight: '600',
  },
  inputGroup: {
    marginTop: 4,
  },
  textArea: {
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 14,
    padding: 14,
    color: Colors.textPrimary,
    fontSize: 13,
    lineHeight: 19,
    minHeight: 120,
  },
  optionalFieldsRow: {
    gap: 8,
  },
  fieldBox: {
    gap: 4,
  },
  fieldLabel: {
    color: Colors.textSecondary,
    fontSize: 11,
    fontWeight: '600',
  },
  inputField: {
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: Colors.textPrimary,
    fontSize: 12,
  },
  switchRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: Colors.surface,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 10,
    marginTop: 4,
  },
  switchLabel: {
    color: Colors.textPrimary,
    fontSize: 12,
    fontWeight: '600',
  },
  submitBtn: {
    backgroundColor: Colors.primary,
    borderRadius: 14,
    paddingVertical: 14,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 8,
  },
  submitBtnDisabled: {
    opacity: 0.5,
  },
  submitBtnText: {
    color: Colors.white,
    fontSize: 13.5,
    fontWeight: '800',
  },
  analyzingRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
});
