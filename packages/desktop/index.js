/**
 * Entry point for the native Windows and macOS apps.
 * The UI is shared with the mobile app (packages/mobile/App.tsx).
 */
import { AppRegistry } from 'react-native';
import App from '../mobile/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
