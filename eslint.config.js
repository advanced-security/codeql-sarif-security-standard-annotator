const typescriptEslint = require('typescript-eslint')
const eslintPluginJest = require('eslint-plugin-jest')
const eslintPluginGithub = require('eslint-plugin-github').default

module.exports = typescriptEslint.config(
  {
    ignores: ['dist/', 'lib/', 'node_modules/', '__tests__/reporters/', 'jest.config.js']
  },
  eslintPluginGithub.getFlatConfigs().recommended,
  ...typescriptEslint.configs.recommended,
  {
    files: ['**/*.ts'],
    plugins: {
      jest: eslintPluginJest
    },
    languageOptions: {
      parser: typescriptEslint.parser,
      parserOptions: {
        ecmaVersion: 9,
        sourceType: 'module',
        project: './tsconfig.json'
      }
    },
    rules: {
      'i18n-text/no-en': 'off',
      'eslint-comments/no-use': 'off',
      'import/no-namespace': 'off',
      'import/no-unresolved': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': 'error',
      '@typescript-eslint/no-require-imports': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-non-null-assertion': 'warn',
      'camelcase': 'off',
      'no-shadow': 'off',
      '@typescript-eslint/no-shadow': 'warn'
    }
  },
  {
    files: ['__tests__/**/*.ts'],
    languageOptions: {
      globals: {
        ...eslintPluginJest.environments.globals.globals
      }
    }
  }
)
