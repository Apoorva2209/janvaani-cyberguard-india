import { NativeModules, PermissionsAndroid, Platform } from 'react-native';

/**
 * Typed wrapper over the native `JanVaaniGuard` module (Android only).
 * On iOS / web / Expo Go the module is absent and every call degrades safely.
 */

export interface GuardStatus {
  supported: boolean;
  enabled: boolean;
  smsPermission: boolean;
  notificationPermission: boolean;
  notificationAccess: boolean;
}

export interface GuardAlert {
  id: string;
  source: string; // "SMS", "WhatsApp", "Gmail", ...
  sender: string;
  excerpt: string;
  level: 'HIGH' | 'MEDIUM' | 'LOW';
  score: number;
  tactics: string[];
  receivedAt: number;
}

interface NativeGuard {
  getStatus(): Promise<Omit<GuardStatus, 'supported'>>;
  setEnabled(enabled: boolean): Promise<boolean>;
  getAlerts(): Promise<string>;
  deleteAlert(id: string): Promise<boolean>;
  clearAlerts(): Promise<boolean>;
  simulate(text: string): Promise<boolean>;
  takeSharedText(): Promise<string | null>;
  openNotificationAccessSettings(): void;
}

const native: NativeGuard | undefined =
  Platform.OS === 'android' ? (NativeModules.JanVaaniGuard as NativeGuard | undefined) : undefined;

export const isGuardSupported = (): boolean => native !== undefined;

const UNSUPPORTED: GuardStatus = {
  supported: false,
  enabled: false,
  smsPermission: false,
  notificationPermission: false,
  notificationAccess: false,
};

export async function getGuardStatus(): Promise<GuardStatus> {
  if (!native) return UNSUPPORTED;
  return { supported: true, ...(await native.getStatus()) };
}

export async function setGuardEnabled(enabled: boolean): Promise<void> {
  await native?.setEnabled(enabled);
}

/** Requests the runtime permissions the guard needs. Returns true if all were granted. */
export async function requestGuardPermissions(): Promise<boolean> {
  if (!native) return false;
  const wanted = [PermissionsAndroid.PERMISSIONS.RECEIVE_SMS];
  if (typeof Platform.Version === 'number' && Platform.Version >= 33) {
    wanted.push(PermissionsAndroid.PERMISSIONS.POST_NOTIFICATIONS);
  }
  const result = await PermissionsAndroid.requestMultiple(wanted);
  return wanted.every((p) => result[p] === PermissionsAndroid.RESULTS.GRANTED);
}

export function openNotificationAccessSettings(): void {
  native?.openNotificationAccessSettings();
}

function isAlert(v: unknown): v is GuardAlert {
  const o = v as Record<string, unknown>;
  return !!o && typeof o.id === 'string' && typeof o.excerpt === 'string' && typeof o.receivedAt === 'number';
}

export async function getAlerts(): Promise<GuardAlert[]> {
  if (!native) return [];
  try {
    const parsed: unknown = JSON.parse(await native.getAlerts());
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isAlert).map((a) => ({
      ...a,
      tactics: Array.isArray(a.tactics) ? a.tactics.map(String) : [],
    }));
  } catch {
    return [];
  }
}

export async function deleteAlert(id: string): Promise<void> {
  await native?.deleteAlert(id);
}

export async function clearAlerts(): Promise<void> {
  await native?.clearAlerts();
}

/** Fires a test alert through the real background pipeline (rules → store → notification). */
export async function simulateAlert(text: string): Promise<void> {
  // A unique suffix bypasses de-duplication so the demo can be repeated.
  await native?.simulate(`${text}\n#test-${Date.now()}`);
}

export async function takeSharedText(): Promise<string | null> {
  if (!native) return null;
  return native.takeSharedText();
}
