import js from '@eslint/js';
import globals from 'globals';
import prettier from 'eslint-plugin-prettier/recommended';

export default [
  js.configs.recommended,
  prettier,
  {
    files: ['spikes/oauth-engine/*.mjs'],
    languageOptions: { sourceType: 'module', globals: globals.node },
  },
];
