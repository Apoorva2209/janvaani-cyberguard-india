const fs = require('fs');
const path = require('path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');
const exclusionList = require('metro-config/src/defaults/exclusionList');

const root = path.resolve(__dirname, '../..');
const mobile = path.resolve(__dirname, '../mobile');
// Directory of an installed package, found through Node's resolver (no path building from strings).
const own = (name) =>
  fs.realpathSync(path.dirname(require.resolve(`${name}/package.json`, { paths: [__dirname] })));

const rnwPath = own('react-native-windows');

// The UI lives in packages/mobile, which resolves `react` and `react-native`
// from the repo root. Force every import onto this package's copies so the
// desktop app never bundles two React Native runtimes.
const singletons = {
  react: own('react'),
  'react-native': own('react-native'),
};

/**
 * Metro configuration for the Windows and macOS apps.
 * https://facebook.github.io/metro/docs/configuration
 *
 * @type {import('metro-config').MetroConfig}
 */
const config = {
  watchFolders: [root, mobile],
  resolver: {
    nodeModulesPaths: [
      path.resolve(__dirname, 'node_modules'),
      path.resolve(root, 'node_modules'),
    ],
    extraNodeModules: singletons,
    blockList: exclusionList([
      // Stops "react-native run-windows" from crashing a running Metro server.
      new RegExp(`${path.resolve(__dirname, 'windows').replace(/[/\\]/g, '/')}.*`),
      // Stops msbuild output from locking files while Metro watches them.
      new RegExp(`${rnwPath}/build/.*`),
      new RegExp(`${rnwPath}/target/.*`),
      /.*\.ProjectImports\.zip/,
      // Native Android and Expo cache folders are irrelevant to the desktop bundle.
      /packages.mobile.android.*/,
      /packages.mobile..expo.*/,
    ]),
    resolveRequest: (context, moduleName, platform) => {
      // On macOS the React Native runtime is the react-native-macos fork.
      if (platform === 'macos') {
        if (moduleName === 'react-native') {
          moduleName = 'react-native-macos';
        } else if (moduleName.startsWith('react-native/')) {
          moduleName = `react-native-macos/${moduleName.slice('react-native/'.length)}`;
        }
      }
      return context.resolveRequest(context, moduleName, platform);
    },
  },
  transformer: {
    getTransformOptions: async () => ({
      transform: {
        experimentalImportSupport: false,
        inlineRequires: true,
      },
    }),
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
