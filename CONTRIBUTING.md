# Contributing to Web Decoy Node.js SDK

Thank you for your interest in contributing to the Web Decoy Node.js SDK! This guide will help you get started.

## Development Setup

1. **Fork and clone the repository:**

```bash
git clone https://github.com/your-username/webdecoy-node.git
cd webdecoy-node
```

2. **Install dependencies:**

```bash
npm install
```

3. **Build all packages:**

```bash
npm run build
```

## Project Structure

```
webdecoy-node/
├── packages/
│   ├── webdecoy/        # Core SDK
│   └── express/         # Express middleware
├── examples/
│   └── express-basic/   # Example applications
├── docs/                # Documentation (coming soon)
└── scripts/             # Build and utility scripts
```

## Development Workflow

### Building Packages

Build all packages:

```bash
npm run build
```

Build in watch mode for development:

```bash
npm run dev
```

Build a specific package:

```bash
cd packages/webdecoy
npm run build
```

### Running Examples

Navigate to an example and run it:

```bash
cd examples/express-basic
cp .env.example .env
# Edit .env with your API key
npm run dev
```

### Linting and Formatting

Run linter:

```bash
npm run lint
```

Format code:

```bash
npm run format
```

### Testing

Run tests:

```bash
npm run test
```

Run tests for a specific package:

```bash
cd packages/webdecoy
npm test
```

## Making Changes

### Creating a New Package

1. Create a new directory under `packages/`
2. Add `package.json` with workspace reference to dependencies
3. Add build configuration (tsconfig.json, tsup config)
4. Update root package.json workspaces if needed

### Creating a New Example

1. Create a new directory under `examples/`
2. Add package.json with workspace references
3. Include a README.md with setup instructions
4. Add .env.example for configuration

### Adding a New Feature

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the code style

3. Add tests for new functionality

4. Update documentation as needed

5. Commit with a clear message:
   ```bash
   git commit -m "Add: Description of your feature"
   ```

6. Push and create a pull request

### Fixing a Bug

1. Create a bug fix branch:
   ```bash
   git checkout -b fix/bug-description
   ```

2. Add a test that reproduces the bug

3. Fix the bug

4. Ensure the test passes

5. Commit and create a pull request

## Code Style

- **TypeScript**: All code should be written in TypeScript
- **Formatting**: Use Prettier (config in .prettierrc)
- **Linting**: Follow ESLint rules
- **Naming**: Use camelCase for variables/functions, PascalCase for classes
- **Comments**: Add JSDoc comments for public APIs

### Example Code Style

```typescript
/**
 * Analyze a request for suspicious patterns
 *
 * @param metadata - Request metadata to analyze
 * @returns Analysis result with threat score
 */
export function analyzeRequest(metadata: RequestMetadata): LocalAnalysis {
  // Implementation
}
```

## Pull Request Process

1. **Update documentation** for any new features
2. **Add tests** for new functionality
3. **Ensure all tests pass** locally
4. **Update CHANGELOG.md** with your changes
5. **Keep commits atomic** - one logical change per commit
6. **Write clear PR descriptions** explaining what and why

### PR Title Format

- `Add: New feature description`
- `Fix: Bug description`
- `Update: Change description`
- `Docs: Documentation update`
- `Refactor: Code refactoring description`

## Testing Guidelines

- Write unit tests for all new functions
- Write integration tests for middleware
- Test error cases and edge cases
- Aim for >80% code coverage

## Documentation

- Update README.md for user-facing changes
- Add JSDoc comments to all public APIs
- Update TypeScript types
- Include code examples where helpful

## Release Process

(For maintainers only)

1. Update version in all package.json files
2. Update CHANGELOG.md
3. Create a git tag
4. Push to GitHub
5. Publish to npm

## Getting Help

- Open an issue for bugs or feature requests
- Join our Discord for questions
- Email support@webdecoy.com for private inquiries

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow the project's coding standards

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to Web Decoy! 🎉
