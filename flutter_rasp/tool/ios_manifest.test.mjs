import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, writeFileSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

test('iOS manifest registers exact protected bytes and does not expose the key on stdout', () => {
  const directory = mkdtempSync(join(tmpdir(), 'rasp-ios-'));
  try {
    writeFileSync(join(directory, 'code'), Buffer.from([1, 2, 3]));
    writeFileSync(join(directory, 'spec.json'), JSON.stringify([{path: 'code', offset: 0, length: 3}]));
    const run = () => spawnSync(process.execPath, [new URL('./ios_manifest.mjs', import.meta.url).pathname,
      directory, join(directory, 'spec.json'), join(directory, 'RaspBuild.json'), 'test.app', join(directory, 'server.json')], {encoding:'utf8'});
    const first = run(); assert.equal(first.status, 0, first.stderr);
    const client = JSON.parse(readFileSync(join(directory, 'RaspBuild.json')));
    const server = JSON.parse(readFileSync(join(directory, 'server.json')));
    assert.equal(Buffer.from(client.buildKey, 'base64').toString('hex'), server.build_key_hex);
    assert.equal(server.build_id, client.buildId);
    assert.equal(server.integrity_root, 'cb264d767858d97f29f903a96fcddeb62da416fd13d9bd37c989925ad9cf3463');
    assert.equal(first.stdout.includes(client.buildKey), false);
    writeFileSync(join(directory, 'code'), Buffer.from([1, 2, 4]));
    const second = run(); assert.equal(second.status, 0, second.stderr);
    assert.notEqual(JSON.parse(second.stdout).integrityRoot, server.integrity_root);
    writeFileSync(join(directory, 'spec.json'), JSON.stringify([{path: '../escape', offset: 0, length: 3}]));
    assert.notEqual(run().status, 0);
  } finally { rmSync(directory, {recursive: true, force: true}); }
});
