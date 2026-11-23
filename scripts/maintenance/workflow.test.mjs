import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const repository = resolve(import.meta.dirname, '../..');
const root = mkdtempSync(join(tmpdir(), 'auth-maintenance-'));
const developer = join(root, 'developer');
const environment = { ...process.env, HUSKY: '1', CI: 'false' };
delete environment.NODE_ENV;
delete environment.npm_config_omit;
delete environment.npm_config_production;
environment.HUSKY_SKIP_HOOKS = '';
environment.XDG_CONFIG_HOME = join(root, 'config');

function run(cwd, command, args, env = environment) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: 'utf8',
    timeout: 180_000,
  });
  if (result.error) throw result.error;
  return result;
}

function success(cwd, command, args, env) {
  const result = run(cwd, command, args, env);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return result.stdout.trim();
}

function fixture(name, git = false) {
  const directory = join(root, name);
  mkdirSync(directory, { recursive: true });
  for (const file of ['package.json', 'package-lock.json']) {
    cpSync(join(repository, file), join(directory, file));
  }
  if (git) {
    success(directory, 'git', ['init', '-q']);
    success(directory, 'git', ['config', 'user.name', 'Maintenance fixture']);
    success(directory, 'git', [
      'config',
      'user.email',
      'fixture@example.invalid',
    ]);
  }
  return directory;
}

before(() => {
  fixture('developer', true);
  for (const file of [
    '.husky/pre-commit',
    '.prettierrc',
    '.prettierignore',
    'lint-staged.config.mjs',
    'scripts/maintenance/check-format.mjs',
    'scripts/maintenance/format-baseline.json',
    'src/iam/config/jwt.config.ts',
    'eslint.config.mjs',
    'tsconfig.json',
    'test/oauth/eslint.config.mjs',
  ]) {
    const target = join(developer, file);
    mkdirSync(resolve(target, '..'), { recursive: true });
    cpSync(join(repository, file), target);
  }
  writeFileSync(
    join(developer, 'eslint-suppressions.json'),
    JSON.stringify({
      'src/iam/config/jwt.config.ts': { 'prettier/prettier': { count: 1 } },
    }),
  );
  success(developer, 'npm', ['ci', '--offline', '--no-audit', '--no-fund']);
  writeFileSync(
    join(developer, 'src/probe.ts'),
    'export const staged = 1;\nexport const unstaged = 1;\n',
  );
  success(developer, 'git', ['add', 'src/probe.ts']);
  success(developer, 'git', [
    '-c',
    'core.hooksPath=/dev/null',
    'commit',
    '-qm',
    'fixture',
  ]);
});

after(() => {
  rmSync(root, { recursive: true, force: true });
});

test('developer install enables a local hook and preserves partial and unstaged changes', () => {
  assert.equal(
    success(developer, 'git', ['config', 'core.hooksPath']),
    '.husky/_',
  );
  const file = join(developer, 'src/probe.ts');
  writeFileSync(file, 'export const staged=2\nexport const unstaged = 1;\n');
  success(developer, 'git', ['add', 'src/probe.ts']);
  writeFileSync(file, 'export const staged=2\nexport const unstaged = 3;\n');
  writeFileSync(join(developer, 'unstaged.txt'), 'untouched canary');
  mkdirSync(join(developer, 'contracts'), { recursive: true });
  writeFileSync(
    join(developer, 'contracts/generated.json'),
    'invalid generated JSON',
  );
  success(developer, 'git', ['add', 'contracts/generated.json']);
  success(developer, 'git', ['commit', '-qm', 'partial staged fixture']);
  assert.equal(
    success(developer, 'git', ['show', 'HEAD:src/probe.ts']),
    'export const staged = 2;\nexport const unstaged = 1;',
  );
  assert.equal(
    readFileSync(file, 'utf8'),
    'export const staged = 2;\nexport const unstaged = 3;\n',
  );
  assert.equal(
    readFileSync(join(developer, 'unstaged.txt'), 'utf8'),
    'untouched canary',
  );
  assert.equal(
    success(developer, 'git', ['show', 'HEAD:contracts/generated.json']),
    'invalid generated JSON',
  );
});

test('a formatter failure blocks commit and restores the staged file', () => {
  const previous = success(developer, 'git', ['rev-parse', 'HEAD']);
  const invalid = 'export const broken = ;\n';
  writeFileSync(join(developer, 'src/broken.ts'), invalid);
  success(developer, 'git', ['add', 'src/broken.ts']);
  const result = run(developer, 'git', ['commit', '-qm', 'must fail']);
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout + result.stderr, /SyntaxError/);
  assert.equal(success(developer, 'git', ['rev-parse', 'HEAD']), previous);
  assert.equal(readFileSync(join(developer, 'src/broken.ts'), 'utf8'), invalid);
  success(developer, 'git', ['rm', '--cached', 'src/broken.ts']);
  rmSync(join(developer, 'src/broken.ts'));
});

test('CI formatting check is non-mutating and rejects new and changed baseline drift', () => {
  success(developer, 'npm', ['run', 'format:check']);
  const file = join(developer, 'src/probe.ts');
  const invalid = 'export const staged=2\nexport const unstaged = 3;\n';
  writeFileSync(file, invalid);
  const result = run(developer, 'npm', ['run', 'format:check']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Formatting violation: src\/probe.ts/);
  assert.equal(readFileSync(file, 'utf8'), invalid);
  writeFileSync(file, 'export const staged = 2;\nexport const unstaged = 3;\n');
  const baselineFile = join(developer, 'src/iam/config/jwt.config.ts');
  writeFileSync(baselineFile, readFileSync(baselineFile, 'utf8') + '\n\n');
  const changed = run(developer, 'npm', ['run', 'format:check']);
  assert.notEqual(changed.status, 0);
  assert.match(
    changed.stderr,
    /Formatting violation: src\/iam\/config\/jwt.config.ts/,
  );
});

test('CI lint gate rejects an unsuppressed new-file violation without mutation', () => {
  const baseline = join(developer, 'src/iam/config/jwt.config.ts');
  cpSync(join(repository, 'src/iam/config/jwt.config.ts'), baseline);
  success(developer, 'npm', ['run', 'lint:check']);
  const file = join(developer, 'src/lint-probe.ts');
  const violation = "export const added = JSON.parse('{}');\n";
  writeFileSync(file, violation);
  const result = run(developer, 'npm', ['run', 'lint:check']);
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout + result.stderr, /no-unsafe-assignment/);
  assert.equal(readFileSync(file, 'utf8'), violation);
  rmSync(file);
});

for (const [name, git, env, args] of [
  ['ci', true, { CI: 'true' }, []],
  ['husky-disabled', true, { HUSKY: '0' }, []],
  ['docker-package-only', false, {}, []],
  ['production-no-dev', true, { NODE_ENV: 'production' }, ['--omit=dev']],
  ['omit-dev', true, {}, ['--omit=dev']],
]) {
  test(`clean ${name} install skips hook setup without skipping dependency scripts`, () => {
    const directory = fixture(name, git);
    success(
      directory,
      'npm',
      ['ci', '--offline', '--no-audit', '--no-fund', ...args],
      {
        ...environment,
        ...env,
      },
    );
    assert.equal(existsSync(join(directory, '.husky/_')), false);
    if (git) {
      assert.notEqual(
        run(directory, 'git', ['config', 'core.hooksPath']).status,
        0,
      );
    }
    success(directory, process.execPath, [
      '-e',
      'require("bcrypt").hashSync("fixture-only",4)',
    ]);
    if (args.includes('--omit=dev')) {
      assert.equal(existsSync(join(directory, 'node_modules/husky')), false);
    }
  });
}
