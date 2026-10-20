/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest/presets/js-with-ts',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/*.test.ts'],
  // js-with-ts: the clearance gate is a generated ES module
  // (src/clearance/gate.generated.js), compiled for jest like the sources.
  transform: {
    '^.+\\.[tj]s$': ['ts-jest', { tsconfig: { allowJs: true } }],
  },
  collectCoverageFrom: ['src/**/*.ts', '!src/**/*.test.ts'],
};
