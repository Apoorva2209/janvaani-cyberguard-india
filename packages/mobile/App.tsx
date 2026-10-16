import React, { useCallback, useEffect, useState } from 'react';
import {
  StyleSheet,
  View,
  SafeAreaView,
  TouchableOpacity,
  Text,
  Linking,
  AppState,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { Colors } from './src/theme/colors';
import { ActiveTab, CheckerModality } from './src/types';
import { useTranslations } from './src/localization/i18n';
import { Header } from './src/components/Header';
import { LanguageModal } from './src/components/LanguageModal';
import { HomeScreen } from './src/screens/HomeScreen';
import { CheckerScreen } from './src/screens/CheckerScreen';
import { LearnScreen } from './src/screens/LearnScreen';
import { HelplineScreen } from './src/screens/HelplineScreen';
import { PrivacyScreen } from './src/screens/PrivacyScreen';
import { ShieldScreen } from './src/screens/ShieldScreen';
import { takeSharedText } from './src/services/guardBridge';

export default function App() {
  const { t } = useTranslations();
  const [activeTab, setActiveTab] = useState<ActiveTab>('check');
  const [activeModality, setActiveModality] = useState<CheckerModality | null>(null);
  const [langModalVisible, setLangModalVisible] = useState<boolean>(false);
  const [, setLangRefresh] = useState<number>(0);
  const [focusAlertId, setFocusAlertId] = useState<string | null>(null);
  const [sharedText, setSharedText] = useState<string | undefined>(undefined);

  // Notification tap -> in.janvaani.cybershield://alert/<id>
  const handleUrl = useCallback((url: string | null) => {
    const m = url?.match(/^in\.janvaani\.cybershield:\/\/alert\/([0-9a-f-]{36})$/i);
    if (m?.[1]) {
      setFocusAlertId(m[1]);
      setActiveTab('shield');
    }
  }, []);

  // Text shared from WhatsApp/Gmail/etc. -> open the message checker pre-filled
  const pullShared = useCallback(async () => {
    const text = await takeSharedText();
    if (text) {
      setSharedText(text);
      setActiveTab('check');
      setActiveModality('message');
    }
  }, []);

  useEffect(() => {
    Linking.getInitialURL().then(handleUrl);
    pullShared();
    const l = Linking.addEventListener('url', (e) => handleUrl(e.url));
    const a = AppState.addEventListener('change', (s) => s === 'active' && pullShared());
    return () => {
      l.remove();
      a.remove();
    };
  }, [handleUrl, pullShared]);

  const handleSelectModality = (modality: CheckerModality) => {
    setActiveModality(modality);
  };

  const handleBackToHome = () => {
    setActiveModality(null);
  };

  const handleLanguageChanged = () => {
    setLangRefresh((prev) => prev + 1);
  };

  return (
    <SafeAreaView style={styles.safeArea}>
      <StatusBar style="light" />

      {/* Top Header */}
      <Header onOpenLanguageModal={() => setLangModalVisible(true)} />

      {/* Main Screen Content */}
      <View style={styles.contentContainer}>
        {activeTab === 'check' && (
          activeModality ? (
            <CheckerScreen
              key={sharedText ?? activeModality}
              initialModality={activeModality}
              initialContent={sharedText}
              onBack={() => {
                setSharedText(undefined);
                handleBackToHome();
              }}
            />
          ) : (
            <HomeScreen
              onSelectModality={handleSelectModality}
              onNavigateToLearn={() => setActiveTab('learn')}
            />
          )
        )}

        {activeTab === 'shield' && (
          <ShieldScreen focusAlertId={focusAlertId} onFocusHandled={() => setFocusAlertId(null)} />
        )}

        {activeTab === 'learn' && <LearnScreen />}

        {activeTab === 'helpline' && <HelplineScreen />}

        {activeTab === 'privacy' && <PrivacyScreen />}
      </View>

      {/* Accessible Bottom Navigation Bar */}
      <View style={styles.bottomNav}>
        <TouchableOpacity
          style={styles.navItem}
          onPress={() => setActiveTab('shield')}
          accessibilityRole="tab"
          accessibilityLabel={t.tabs.shield}
        >
          <Text style={[styles.navIcon, activeTab === 'shield' && styles.navIconActive]}>🚨</Text>
          <Text style={[styles.navLabel, activeTab === 'shield' && styles.navLabelActive]}>
            {t.tabs.shield}
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={styles.navItem}
          onPress={() => {
            setActiveTab('check');
            setActiveModality(null);
          }}
          accessibilityRole="tab"
          accessibilityLabel={t.tabs.check}
        >
          <Text style={[styles.navIcon, activeTab === 'check' && styles.navIconActive]}>
            🛡️
          </Text>
          <Text
            style={[styles.navLabel, activeTab === 'check' && styles.navLabelActive]}
          >
            {t.tabs.check}
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.navItem}
          onPress={() => setActiveTab('learn')}
          accessibilityRole="tab"
          accessibilityLabel={t.tabs.learn}
        >
          <Text style={[styles.navIcon, activeTab === 'learn' && styles.navIconActive]}>
            💡
          </Text>
          <Text
            style={[styles.navLabel, activeTab === 'learn' && styles.navLabelActive]}
          >
            {t.tabs.learn}
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.navItem}
          onPress={() => setActiveTab('helpline')}
          accessibilityRole="tab"
          accessibilityLabel={t.tabs.helpline}
        >
          <Text style={[styles.navIcon, activeTab === 'helpline' && styles.navIconActive]}>
            📞
          </Text>
          <Text
            style={[styles.navLabel, activeTab === 'helpline' && styles.navLabelActive]}
          >
            {t.tabs.helpline}
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.navItem}
          onPress={() => setActiveTab('privacy')}
          accessibilityRole="tab"
          accessibilityLabel={t.tabs.privacy}
        >
          <Text style={[styles.navIcon, activeTab === 'privacy' && styles.navIconActive]}>
            🔒
          </Text>
          <Text
            style={[styles.navLabel, activeTab === 'privacy' && styles.navLabelActive]}
          >
            {t.tabs.privacy}
          </Text>
        </TouchableOpacity>
      </View>

      {/* Language Modal */}
      <LanguageModal
        visible={langModalVisible}
        onClose={() => setLangModalVisible(false)}
        onSelectLanguage={handleLanguageChanged}
      />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: Colors.background,
  },
  contentContainer: {
    flex: 1,
  },
  bottomNav: {
    flexDirection: 'row',
    backgroundColor: Colors.surface,
    borderTopWidth: 1,
    borderTopColor: Colors.border,
    paddingVertical: 10,
    paddingHorizontal: 12,
  },
  navItem: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 3,
  },
  navIcon: {
    fontSize: 18,
    opacity: 0.6,
  },
  navIconActive: {
    opacity: 1,
  },
  navLabel: {
    fontSize: 11,
    fontWeight: '600',
    color: Colors.textSecondary,
  },
  navLabelActive: {
    color: Colors.white,
    fontWeight: '800',
  },
});
