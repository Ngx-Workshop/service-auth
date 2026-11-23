import { createHash } from 'node:crypto';
import { globSync, readFileSync } from 'node:fs';
import { check, getFileInfo, resolveConfig } from 'prettier';

const baseline = JSON.parse(
  readFileSync(new URL('./format-baseline.json', import.meta.url), 'utf8'),
);
const files = globSync([
  'src/**/*.ts',
  'test/**/*.ts',
  'libs/**/*.ts',
  'scripts/maintenance/*.mjs',
  'lint-staged.config.mjs',
  'package.json',
  '.prettierrc',
  '.github/workflows/*.yml',
  'docs/architecture.md',
  'docs/development.md',
  'docs/observability.md',
  'specs/006-code-maintenance/*.md',
]);
let failed = false;
for (const file of files) {
  const info = await getFileInfo(file, { ignorePath: '.prettierignore' });
  if (info.ignored) continue;
  const content = readFileSync(file, 'utf8');
  if (await check(content, { ...(await resolveConfig(file)), filepath: file }))
    continue;
  const digest = createHash('sha256').update(content).digest('hex');
  if (baseline[file] === digest) {
    console.warn(`Existing formatting baseline (unchanged): ${file}`);
  } else {
    console.error(`Formatting violation: ${file}`);
    failed = true;
  }
}
process.exitCode = failed ? 1 : 0;
