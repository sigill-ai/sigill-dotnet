// Reference answers: runs every case in cases.json through @cedar-policy/cedar-wasm 4.14.0.
// usage: node ref.mjs <cases.json> <out.json>   (run from the directory holding node_modules)
import { readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
const cedar = createRequire(process.cwd() + '/')('@cedar-policy/cedar-wasm/nodejs')
const [casesPath, outPath] = process.argv.slice(2)
const cases = JSON.parse(readFileSync(casesPath, 'utf8'))
writeFileSync(outPath, JSON.stringify({
  version: cedar.getCedarVersion(),
  authorize: cases.authorize.map(c => cedar.isAuthorized(c.call)),
  validate: cases.validate.map(c => cedar.validate(c.call)),
}))
console.log(`reference cedar-wasm getCedarVersion()=${cedar.getCedarVersion()} authorize=${cases.authorize.length} validate=${cases.validate.length}`)
