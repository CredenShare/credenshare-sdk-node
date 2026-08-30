// Run the test suite portably.
//
// `node --test test/*.test.ts` works on any shell that expands globs and fails on the one that
// does not. CI proved it: every Linux and macOS job passed while `node 20 on windows-latest`
// died with `Could not find 'D:\a\...\test\*.test.ts'` — PowerShell hands the literal string to
// Node, and Node's own glob support in `--test` only arrived in 21, so 18 and 20 cannot rescue
// it either.
//
// Passing the directory instead is not a fix: Node's default test-file discovery matches
// `*.test.{js,mjs,cjs}`, and the TypeScript extensions were added later than the versions this
// package supports.
//
// So the files are discovered here and passed explicitly. Discovery rather than a hand-written
// list on purpose — a list in package.json silently stops running a test file the day somebody
// adds one and forgets to register it, and a suite that quietly shrinks still reports success.
import { readdirSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve } from 'node:path'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const testDir = join(root, 'test')

const files = readdirSync(testDir)
  .filter((name) => name.endsWith('.test.ts'))
  .sort()
  .map((name) => join('test', name))

if (files.length === 0) {
  console.error('no test files found in test/ — refusing to report success on an empty run')
  process.exit(1)
}

console.log(`running ${files.length} test file(s): ${files.join(', ')}`)

const result = spawnSync(
  process.execPath,
  ['--import', 'tsx', '--test', ...files, ...process.argv.slice(2)],
  { cwd: root, stdio: 'inherit' },
)

process.exit(result.status ?? 1)
