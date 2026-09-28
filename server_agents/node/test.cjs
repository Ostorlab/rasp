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

test('short sources, quoted values and identifier substrings permit parameterized SQL', () => {
  const client = agent.protectSqlClient({ query(text, values) { return values; } });
  agent.withRequest({tenantId:'a',requestId:'sql',sources:['1','id','alice','user']},{},()=>{
    assert.deepEqual(client.query("select $1 as user_name, 'alice' limit 10",['1']),['1']);
  });
});

test('dangling links emit redacted denials and allow in-root targets', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rasp-links-'));
  try {
    fs.mkdirSync(root+'/allowed'); fs.mkdirSync(root+'/outside');
    fs.symlinkSync(root+'/outside/new',root+'/allowed/bad');
    fs.symlinkSync('new',root+'/allowed/good');
    agent.withRequest({tenantId:'a',requestId:'links'},{allowedRoots:[root+'/allowed']},scope=>{
      assert.throws(()=>fs.writeFileSync(root+'/allowed/bad','secret'),agent.Blocked);
      assert.equal(scope.events[0].reason,'outside_allowed_roots');
      fs.writeFileSync(root+'/allowed/good','ok');
    });
    assert.equal(fs.readFileSync(root+'/allowed/new','utf8'),'ok');
  } finally {fs.rmSync(root,{recursive:true});}
});

test('delete rename copy symlink and listing enforce both file operands', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rasp-ops-'));
  try {
    fs.mkdirSync(root+'/allowed'); fs.mkdirSync(root+'/outside');
    fs.writeFileSync(root+'/allowed/safe','safe');fs.writeFileSync(root+'/outside/secret','secret');
    const source=root+'/outside/secret', safe=root+'/allowed/safe';
    await agent.withRequest({tenantId:'a',requestId:'ops'},{allowedRoots:[root+'/allowed']}, async scope=>{
      const operations=[()=>fs.unlinkSync(source),()=>fs.rmSync(root+'/outside',{recursive:true}),
        ()=>fs.renameSync(source,root+'/allowed/new'),()=>fs.renameSync(safe,root+'/outside/new'),
        ()=>fs.copyFileSync(source,root+'/allowed/new'),()=>fs.copyFileSync(safe,root+'/outside/new'),
        ()=>fs.cpSync(root+'/outside',root+'/allowed/new',{recursive:true}),
        ()=>fs.symlinkSync(source,root+'/allowed/link'),()=>fs.symlinkSync('../outside/secret',root+'/allowed/link'),
        ()=>fs.symlinkSync(safe,root+'/outside/link'),()=>fs.readdirSync(root+'/outside'),()=>fs.opendirSync(root+'/outside')];
      for(const operation of operations) assert.throws(operation,agent.Blocked);
      await assert.rejects(fs.promises.unlink(source),agent.Blocked);
      await assert.rejects(fs.promises.rename(safe,root+'/outside/new'),agent.Blocked);
      await assert.rejects(fs.promises.copyFile(source,root+'/allowed/new'),agent.Blocked);
      await assert.rejects(fs.promises.symlink(source,root+'/allowed/link'),agent.Blocked);
      await assert.rejects(fs.promises.readdir(root+'/outside'),agent.Blocked);
      assert.equal(scope.events.length,operations.length+5);
    });
    assert.equal(fs.readFileSync(source,'utf8'),'secret');assert.equal(fs.readFileSync(safe,'utf8'),'safe');
  } finally {fs.rmSync(root,{recursive:true});}
});

test('mapped public IPv6 reaches transport without a policy denial', async () => {
  // Stub transport only: public Internet access must never be needed by the test.
  const probe = require('node:child_process').spawnSync(process.execPath,['-e',`
    const assert=require('node:assert/strict'), net=require('node:net');
    let calls=0; net.Socket.prototype.connect=function(){ calls++; return this; };
    const agent=require('./index.cjs'); agent.install();
    agent.withRequest({tenantId:'a',requestId:'mapped'},{},()=>{
      for(const host of ['::ffff:8.8.8.8','::ffff:808:808']) net.connect({host,port:443});
      assert.throws(()=>net.connect({host:'::ffff:7f00:1',port:9}),agent.Blocked);
    }); assert.equal(calls,2);
  `],{cwd:__dirname,encoding:'utf8'});
  assert.equal(probe.status,0,probe.stderr);
});

test('recursive copies cannot read or recreate escaping symlinks', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rasp-recursive-'));
  try {
    fs.mkdirSync(root+'/allowed/source',{recursive:true});fs.mkdirSync(root+'/outside');
    fs.writeFileSync(root+'/outside/secret','secret');fs.symlinkSync(root+'/outside/secret',root+'/allowed/source/link');
    await agent.withRequest({tenantId:'a',requestId:'recursive'},{allowedRoots:[root+'/allowed']},async()=>{
      assert.throws(()=>fs.cpSync(root+'/allowed/source',root+'/allowed/copy',{recursive:true,dereference:true}),agent.Blocked);
      await assert.rejects(fs.promises.cp(root+'/allowed/source',root+'/allowed/copy',{recursive:true}),agent.Blocked);
    });
    assert.equal(fs.existsSync(root+'/allowed/copy'),false);
  } finally {fs.rmSync(root,{recursive:true});}
});

test('in-root file mutations preserve callback sync and promise APIs', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rasp-safe-'));
  try {
    await agent.withRequest({tenantId:'a',requestId:'safe'},{allowedRoots:[root]},async()=>{
      fs.mkdirSync(root+'/source');fs.writeFileSync(root+'/source/file','safe');
      fs.symlinkSync('file',root+'/source/link');
      fs.cpSync(root+'/source',root+'/copy',{recursive:true});
      assert.equal(fs.readFileSync(root+'/copy/link','utf8'),'safe');
      await fs.promises.rename(root+'/copy/file',root+'/copy/renamed');
      assert.ok((await fs.promises.readdir(root+'/copy')).includes('renamed'));
      await new Promise((resolve,reject)=>fs.unlink(root+'/copy/link',error=>error?reject(error):resolve()));
      await fs.promises.rm(root+'/copy',{recursive:true});
    });
  } finally {fs.rmSync(root,{recursive:true});}
});

test('denials retain at most 100 events with only approved fields', () => {
  agent.withRequest({tenantId:'a',requestId:'events',sources:['attack']},{},scope=>{
    for(let index=0;index<105;index++) assert.throws(()=>agent.checkSql('select attack'),agent.Blocked);
    assert.equal(scope.events.length,100);
    assert.deepEqual(Object.keys(scope.events[0]).sort(),['reason','requestId','sink','tenantId']);
  });
});
