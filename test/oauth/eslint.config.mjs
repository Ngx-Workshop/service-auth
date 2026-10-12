import js from '@eslint/js';
import globals from 'globals';
import prettier from 'eslint-plugin-prettier/recommended';

export default [
  js.configs.recommended,
  prettier,
  {
    files: [
      'src/oauth/*.mjs',
      'test/oauth/*.mjs',
      'scripts/oauth-local-config.mjs',
      'scripts/oauth-mongo-provision.mjs',
    ],
    languageOptions: { sourceType: 'module', globals: globals.node },
  },
];
