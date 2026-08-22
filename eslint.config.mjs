// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

/**
 * One flat config for the whole workspace.
 *
 * Every package declared eslint and @typescript-eslint as devDependencies and
 * ran `eslint src/**\/*.ts`, and there was no config file anywhere in the tree —
 * so `npm run lint` exited 2 in all five, and had since the repo was created.
 * Nothing was gating on it, so it went unnoticed.
 *
 * Rather than five copies of the same config, the toolchain lives at the root
 * and each package's script points here. The ruleset is deliberately narrow:
 * type checking is TypeScript's job and formatting is Prettier's, so what is
 * left is the class of thing neither catches — an unhandled promise, a name
 * that is defined and never used, a `case` that falls through.
 */
export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/coverage/**',
      '**/.turbo/**',
      // Generated from the Go agent registry (`pkg/cmd/export-agent-registry`).
      // Lint findings here are not actionable: the fix belongs in the
      // generator, and the file is overwritten on every regeneration.
      '**/*.generated.ts',
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    files: ['**/*.ts'],
    languageOptions: {
      parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
      globals: { ...globals.node, ...globals.browser },
    },
    rules: {
      // An unused argument is usually a signature the runtime dictates —
      // middleware `next`, a handler's `res`. Underscore marks it deliberate.
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrors: 'all',
          caughtErrorsIgnorePattern: '^_',
        },
      ],

      // `any` is load-bearing in a few places where we accept whatever a
      // framework hands us. It is still worth seeing, so: a warning, and CI
      // does not allow the count to grow (see the --max-warnings budget in the
      // lint script).
      '@typescript-eslint/no-explicit-any': 'warn',

      // `declare global { namespace Express { … } }` is the only way to augment
      // a framework's types. The rule's real target is a namespace used as a
      // module, which `allowDeclarations` still forbids.
      '@typescript-eslint/no-namespace': ['error', { allowDeclarations: true }],

      'no-console': 'off', // the SDK logs through console by design (`debug: true`)
      eqeqeq: ['error', 'always', { null: 'ignore' }],
      'no-fallthrough': 'error',
    },
  },

  {
    files: ['**/*.test.ts', '**/*.spec.ts'],
    languageOptions: {
      globals: { ...globals.jest },
    },
    rules: {
      // Tests reach into internals and hand-build malformed input on purpose.
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },

  {
    files: ['**/*.mjs', '**/*.js'],
    languageOptions: {
      globals: { ...globals.node },
    },
  },
);
