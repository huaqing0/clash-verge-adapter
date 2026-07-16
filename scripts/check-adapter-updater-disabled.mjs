import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const readJson = async (relativePath) =>
  JSON.parse(await readFile(join(root, relativePath), 'utf8'))

const baseConfig = await readJson('src-tauri/tauri.conf.json')
assert.equal(
  baseConfig.bundle?.createUpdaterArtifacts,
  false,
  'Adapter builds must not generate upstream updater artifacts',
)
assert.deepEqual(
  baseConfig.plugins?.updater?.endpoints,
  [],
  'Base Tauri config must not contain updater endpoints',
)

const tauriConfigPaths = (await readdir(join(root, 'src-tauri')))
  .filter((name) => name.endsWith('.json'))
  .map((name) => `src-tauri/${name}`)

for (const configPath of tauriConfigPaths) {
  const config = await readJson(configPath)
  if (config.plugins?.updater) {
    assert.deepEqual(
      config.plugins.updater.endpoints,
      [],
      `${configPath} must not re-enable updater endpoints`,
    )
  }
}

const capabilityPaths = (await readdir(join(root, 'src-tauri/capabilities')))
  .filter((name) => name.endsWith('.json'))
  .map((name) => `src-tauri/capabilities/${name}`)
for (const capabilityPath of capabilityPaths) {
  const capabilities = await readJson(capabilityPath)
  assert.equal(
    capabilities.permissions.some(
      (permission) =>
        typeof permission === 'string' && permission.startsWith('updater:'),
    ),
    false,
    `${capabilityPath} must not grant updater permissions`,
  )
}

const manifest = await readJson('src-tauri/resources/adapter-manifest.json')
assert.equal(
  manifest.upstreamUpdaterPolicy,
  'disabled',
  'Adapter manifest must declare its upstream updater policy',
)

const guardedSources = [
  'src/services/update.ts',
  'src-tauri/src/utils/resolve/mod.rs',
]
for (const sourcePath of guardedSources) {
  const source = await readFile(join(root, sourcePath), 'utf8')
  assert.match(
    source,
    /upstream updater disabled|UPSTREAM_UPDATES_DISABLED/i,
    `${sourcePath} must retain an explicit runtime updater guard`,
  )
}

console.log('Adapter upstream updater policy: disabled (config, UI, runtime)')
