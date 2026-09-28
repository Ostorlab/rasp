'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const child = require('node:child_process');
const net = require('node:net');
const agent = require('./index.cjs');
agent.install();

test('shell and process execution are blocked before side effects', () => {
  agent.withRequest({ tenantId: 'a', requestId: '1', sources: [] }, {}, () => {
    assert.throws(() => child.execSync('printf bad'), agent.Blocked);
    assert.throws(() => child.spawnSync(process.execPath, ['-e', 'process.exit(0)']), agent.Blocked);
    assert.throws(() => child.fork(__filename), agent.Blocked);
  });
});

test('explicitly allowed executable and file roots work', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rasp-agent-'));
  try {
    agent.withRequest({ tenantId: 'a', requestId: '1', sources: [] },
      { allowedRoots: [root], allowedExecutables: [fs.realpathSync(process.execPath)] }, () => {
        fs.writeFileSync(path.join(root, 'ok'), 'ok');
        assert.equal(fs.readFileSync(path.join(root, 'ok'), 'utf8'), 'ok');
        assert.throws(() => fs.readFileSync('/etc/passwd'), agent.Blocked);
        assert.equal(child.execFileSync(process.execPath, ['-e', 'process.stdout.write("ok")']).toString(), 'ok');
        assert.throws(() => child.fork(__filename, [], {execPath:'/bin/sh'}), agent.Blocked);
      });
  } finally { fs.rmSync(root, { recursive: true }); }
});

test('SQL source values are blocked in statements and stay allowed as parameters', () => {
  const calls = [];
  const client = { query(statement, params) { calls.push([statement, params]); } };
  agent.protectSqlClient(client);
  agent.withRequest({ tenantId: 'a', requestId: '1', sources: ["' OR 1=1 --"] }, {}, () => {
    assert.throws(() => client.query("select * from users where name='' OR 1=1 --'"), agent.Blocked);
    client.query('select * from users where name=$1', ["' OR 1=1 --"]);
  });
  assert.equal(calls.length, 1);
});

test('symlink followed by parent traversal cannot escape the allowed root', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rasp-traversal-'));
  try {
    fs.mkdirSync(root+'/allowed'); fs.mkdirSync(root+'/outside/sub',{recursive:true});
    fs.writeFileSync(root+'/outside/secret','private');
    fs.symlinkSync(root+'/outside/sub',root+'/allowed/link');
    agent.withRequest({tenantId:'a',requestId:'traversal'},{allowedRoots:[root+'/allowed']},()=>{
      assert.throws(()=>fs.readFileSync(root+'/allowed/link/../secret'),agent.Blocked);
      assert.throws(()=>fs.writeFileSync(root+'/allowed/link/../new','forbidden'),agent.Blocked);
    });
    assert.equal(fs.existsSync(root+'/outside/new'),false);
  } finally { fs.rmSync(root,{recursive:true}); }
});

test('dangling symlink cannot redirect a new write outside an allowed root', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rasp-dangling-'));
  try {
    fs.mkdirSync(root+'/allowed'); fs.mkdirSync(root+'/outside');
    fs.symlinkSync(root+'/outside/new',root+'/allowed/link');
    agent.withRequest({tenantId:'a',requestId:'dangling'},{allowedRoots:[root+'/allowed']},()=>{
      assert.throws(()=>fs.writeFileSync(root+'/allowed/link','forbidden'));
    });
    assert.equal(fs.existsSync(root+'/outside/new'),false);
  } finally { fs.rmSync(root,{recursive:true}); }
});

test('file streams enforce roots and filesystem root includes descendants', () => {
  agent.withRequest({ tenantId: 'a', requestId: 'stream' }, {}, () => {
    assert.throws(() => fs.createReadStream('/etc/passwd'), agent.Blocked);
    assert.throws(() => fs.createWriteStream('/tmp/rasp-forbidden-stream'), agent.Blocked);
  });
  agent.withRequest({ tenantId: 'a', requestId: 'root' }, { allowedRoots: ['/'] }, () => {
    assert.ok(fs.readFileSync(__filename).length > 0);
  });
});

test('explicit allowed address connects to a real TCP server', async () => {
  const server = net.createServer(socket => socket.end('ok'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await agent.withRequest({ tenantId: 'a', requestId: 'tcp' },
      { allowedAddresses: ['127.0.0.1'] }, () => new Promise((resolve, reject) => {
        const socket = net.connect(server.address().port, '127.0.0.1');
        let data = '';
        socket.setEncoding('utf8');
        socket.on('data', chunk => { data += chunk; });
        socket.on('end', () => resolve(data));
        socket.on('error', reject);
      }));
    assert.equal(result, 'ok');
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('loopback and mapped loopback are blocked before a socket connects', () => {
  agent.withRequest({ tenantId: 'a', requestId: '1', sources: [] }, {}, () => {
    for (const host of ['127.0.0.1', '::1', '::ffff:127.0.0.1']) {
      assert.throws(() => net.connect({ host, port: 9 }), error => error instanceof agent.Blocked && error.event.reason === 'nonpublic_address');
    }
  });
});

test('DNS results are checked before connection even with a custom resolver', async () => {
  await agent.withRequest({ tenantId: 'a', requestId: 'dns', sources: [] }, {}, () => new Promise((resolve, reject) => {
    const connection = net.connect({ host: 'example.test', port: 9,
      lookup(host, options, callback) {
        if (options.all) callback(null, [{ address: '127.0.0.1', family: 4 }]);
        else callback(null, '127.0.0.1', 4);
      } });
    connection.once('connect', () => { connection.destroy(); reject(new Error('forbidden connection')); });
    connection.once('error', error => { assert.ok(error instanceof agent.Blocked); resolve(); });
  }));
});

test('async tenant request contexts remain isolated', async () => {
  const results = await Promise.all(['a', 'b'].map(tenantId => agent.withRequest(
    { tenantId, requestId: '1', sources: ['attack'] }, {}, async scope => {
      await Promise.resolve();
      assert.throws(() => agent.checkSql('select attack'), agent.Blocked);
      return scope.events[0].tenantId;
    })));
  assert.deepEqual(results, ['a', 'b']);
});
