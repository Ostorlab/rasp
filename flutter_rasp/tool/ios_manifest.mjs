#!/usr/bin/env node
// Private post-build integrity manifest generator. Never print or commit buildKey.
import { readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

const [bundleArgument, specification, output, bundleId, serverOutput] = process.argv.slice(2);
if (!bundleArgument || !specification || !output || !bundleId || !serverOutput) {
  throw new Error('Usage: node ios_manifest.mjs APP_BUNDLE REGION_SPEC_JSON OUTPUT_JSON BUNDLE_ID PRIVATE_SERVER_MANIFEST');
}
const bundle = realpathSync(bundleArgument);
const specs = JSON.parse(readFileSync(specification, 'utf8'));
if (!Array.isArray(specs) || specs.length < 1 || specs.length > 512) throw new Error('1..512 regions required');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const regions = specs.map(({path, offset, length}) => {
  if (typeof path !== 'string' || path.includes('\n') || !Number.isSafeInteger(offset) || offset < 0 ||
      !Number.isSafeInteger(length) || length < 1 || length > 16 * 1024 * 1024) throw new Error('Invalid region');
  const source = realpathSync(resolve(bundle, path));
  if (!source.startsWith(bundle + sep)) throw new Error('Region escapes bundle');
  if (source === resolve(output)) throw new Error('Manifest cannot hash itself');
  const bytes = readFileSync(source).subarray(offset, offset + length);
  if (bytes.length !== length) throw new Error('Truncated region');
  return {path, offset, length, sha256: hash(bytes)};
}).sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : left.offset - right.offset);
const canonical = 'rasp-ios-integrity-1\n' + regions.map(r => `${r.path}\n${r.offset}\n${r.length}\n${r.sha256}\n`).join('');
const buildId = 'ios-' + randomBytes(16).toString('hex');
const manifest = {buildId, buildKey: randomBytes(32).toString('base64'), regions};
writeFileSync(output, JSON.stringify(manifest, null, 2) + '\n', {mode: 0o600});
const integrityRoot = hash(Buffer.from(canonical));
writeFileSync(serverOutput, JSON.stringify({build_id: buildId, build_key_hex: Buffer.from(manifest.buildKey, 'base64').toString('hex'),
  package_name: bundleId, signing_cert_sha256: [], integrity_root: integrityRoot}, null, 2) + '\n', {mode: 0o600});
process.stdout.write(JSON.stringify({buildId, integrityRoot}) + '\n');
