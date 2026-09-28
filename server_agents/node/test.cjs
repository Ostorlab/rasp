'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const child = require('node:child_process');
const net = require('node:net');
const dns = require('node:dns');
const agent = require('./index.cjs');
agent.install();

test('relative traversal symlinks deny outside reads', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rasp-relative-'));
  try {
    fs.mkdirSync(root + '/allowed/sub', { recursive: true });
    fs.mkdirSync(root + '/outside');
    fs.writeFileSync(root + '/outside/secret', 'secret');
    fs.symlinkSync('../../outside/secret', root + '/allowed/sub/link');
    agent.withRequest({ tenantId: 'a', requestId: 'relative' }, { allowedRoots: [root + '/allowed'] }, scope => {
      assert.throws(() => fs.readFileSync(root + '/allowed/sub/link'), agent.Blocked);
      assert.equal(scope.events[0].reason, 'outside_allowed_roots');
    });
  } finally { fs.rmSync(root, { recursive: true }); }
});

test('dereferenced direct copies resolve relative targets at the source parent', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rasp-copy-relative-'));
  try {
    fs.mkdirSync(root + '/allowed/source/sub', { recursive: true });
    fs.mkdirSync(root + '/allowed/output');
    fs.writeFileSync(root + '/allowed/source/file', 'safe');
    fs.symlinkSync('../file', root + '/allowed/source/sub/link');
    await agent.withRequest({ tenantId: 'a', requestId: 'copy-relative' },
      { allowedRoots: [root + '/allowed/source', root + '/allowed/output'] }, async () => {
        // Node 22.14 cpSync requires recursive even for a dereferenced file symlink.
        fs.cpSync(root + '/allowed/source/sub/link', root + '/allowed/output/sync', { recursive: true, dereference: true });
        await fs.promises.cp(root + '/allowed/source/sub/link', root + '/allowed/output/promise', { dereference: true });
      });
    assert.equal(fs.readFileSync(root + '/allowed/output/sync', 'utf8'), 'safe');
    assert.equal(fs.readFileSync(root + '/allowed/output/promise', 'utf8'), 'safe');
  } finally { fs.rmSync(root, { recursive: true }); }
});

test('nonrecursive direct copies deny dereferenced outside targets', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rasp-copy-direct-'));
  try {
    fs.mkdirSync(root + '/allowed/sub', { recursive: true });
    fs.mkdirSync(root + '/outside');
    fs.writeFileSync(root + '/outside/secret', 'secret');
    fs.symlinkSync('../../outside/secret', root + '/allowed/sub/link');
    await agent.withRequest({ tenantId: 'a', requestId: 'copy-direct' }, { allowedRoots: [root + '/allowed'] }, async () => {
      assert.throws(() => fs.cpSync(root + '/allowed/sub/link', root + '/allowed/sync', { dereference: true }), agent.Blocked);
      await assert.rejects(new Promise((resolve, reject) => fs.cp(root + '/allowed/sub/link', root + '/allowed/callback',
        { dereference: true }, error => error ? reject(error) : resolve())), agent.Blocked);
    });
    assert.equal(fs.existsSync(root + '/allowed/sync'), false);
    assert.equal(fs.existsSync(root + '/allowed/callback'), false);
  } finally { fs.rmSync(root, { recursive: true }); }
});

test('numeric descriptors preserve supported file calls and native argument errors', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rasp-descriptor-'));
  const file = root + '/file';
  fs.writeFileSync(file, 'safe');
  const descriptor = fs.openSync(file, 'r+');
  try {
    await agent.withRequest({ tenantId: 'a', requestId: 'descriptor' }, {}, async () => {
      fs.writeFileSync(descriptor, 'sync');
      fs.appendFileSync(descriptor, ' appended');
      fs.truncateSync(descriptor, 4);
      await new Promise((resolve, reject) => fs.writeFile(descriptor, 'call', error => error ? reject(error) : resolve()));
      await new Promise((resolve, reject) => fs.appendFile(descriptor, ' appended', error => error ? reject(error) : resolve()));
      await new Promise((resolve, reject) => fs.truncate(descriptor, 4, error => error ? reject(error) : resolve()));
      assert.equal(typeof fs.readFileSync(descriptor, 'utf8'), 'string');
      assert.equal(typeof await new Promise((resolve, reject) => fs.readFile(descriptor, 'utf8',
        (error, data) => error ? reject(error) : resolve(data))), 'string');
      for (const operation of [() => fs.openSync(descriptor, 'r'), () => fs.chmodSync(descriptor, 0o600),
        () => fs.chownSync(descriptor, 0, 0), () => fs.utimesSync(descriptor, 0, 0)]) {
        assert.throws(operation, error => error.code === 'ERR_INVALID_ARG_TYPE');
      }
      assert.throws(() => fs.readFileSync(file), agent.Blocked);
    });
  } finally { fs.closeSync(descriptor); fs.rmSync(root, { recursive: true }); }
});

test('Promise DNS resolvers validate private single and all address results', async () => {
  for (const all of [false, true]) {
    await agent.withRequest({ tenantId: 'a', requestId: 'promise-dns' }, {}, () => new Promise((resolve, reject) => {
      const socket = net.connect({ host: 'localhost', port: 9, autoSelectFamily: all, lookup: dns.promises.lookup });
      const timeout = setTimeout(() => { socket.destroy(); reject(new Error('Promise resolver did not report denial')); }, 250);
      socket.once('connect', () => { clearTimeout(timeout); socket.destroy(); reject(new Error('private connection allowed')); });
      socket.once('error', error => { clearTimeout(timeout); try { assert.ok(error instanceof agent.Blocked); resolve(); } catch (failure) { reject(failure); } });
    }));
  }
});

test('allowed Promise DNS results preserve Socket returns and connect callbacks', async () => {
  const server = net.createServer(socket => socket.end('ok'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    for (const all of [false, true]) {
      let callbacks = 0;
      const result = await agent.withRequest({ tenantId: 'a', requestId: 'promise-connect' },
        { allowedAddresses: ['127.0.0.1'] }, () => new Promise((resolve, reject) => {
          const socket = net.connect({ host: 'example.test', port: server.address().port, autoSelectFamily: all,
            lookup: (hostname, options) => dns.promises.lookup('127.0.0.1', options) }, () => { callbacks++; });
          assert.ok(socket instanceof net.Socket);
          let data = '';
          socket.setEncoding('utf8');
          socket.on('data', chunk => { data += chunk; });
          socket.on('end', () => resolve(data));
          socket.on('error', reject);
        }));
      assert.equal(result, 'ok');
      assert.equal(callbacks, 1);
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('native callback DNS lookup preserves its opaque request return contract', async () => {
  const server = net.createServer(socket => socket.end('ok'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    for (const lookup of [undefined, dns.lookup]) {
      const result = await agent.withRequest({ tenantId: 'a', requestId: 'native-dns' },
        { allowedAddresses: ['127.0.0.1'] }, () => new Promise((resolve, reject) => {
          const socket = net.connect({ host: 'localhost', port: server.address().port, family: 4,
            autoSelectFamily: false, lookup });
          let data = '';
          socket.setEncoding('utf8');
          socket.on('data', chunk => { data += chunk; });
          socket.on('end', () => resolve(data));
          socket.on('error', reject);
        }));
      assert.equal(result, 'ok');
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('unsupported DNS resolver return forms fail closed', () => {
  for (const lookup of [() => '127.0.0.1', () => ({ address: '127.0.0.1', family: 4 })]) {
    agent.withRequest({ tenantId: 'a', requestId: 'unsupported-dns' }, {}, () => {
      assert.throws(() => net.connect({ host: 'example.test', port: 9, lookup }),
        error => error instanceof agent.Blocked && error.event.reason === 'unsupported_lookup_form');
    });
  }
});

test('default and rest callback DNS resolver signatures deny private addresses', async () => {
  const resolvers = [
    function(host, options = {}, callback) {
      if (options.all) callback(null, [{ address: '127.0.0.1', family: 4 }]);
      else callback(null, '127.0.0.1', 4);
    },
    function(...args) {
      const [, options, callback] = args;
      process.nextTick(() => {
        if (options.all) callback(null, [{ address: '127.0.0.1', family: 4 }]);
        else callback(null, '127.0.0.1', 4);
      });
    }
  ];
  for (const lookup of resolvers) {
    await agent.withRequest({ tenantId: 'a', requestId: 'callback-signature' }, {}, () => new Promise((resolve, reject) => {
      const socket = net.connect({ host: 'example.test', port: 9, lookup });
      const timeout = setTimeout(() => { socket.destroy(); reject(new Error('callback resolver did not report denial')); }, 250);
      socket.once('connect', () => { clearTimeout(timeout); socket.destroy(); reject(new Error('private connection allowed')); });
      socket.once('error', error => { clearTimeout(timeout); try { assert.ok(error instanceof agent.Blocked); resolve(); } catch (failure) { reject(failure); } });
    }));
  }
});

test('three argument Promise DNS resolvers deny private addresses', async () => {
  await agent.withRequest({ tenantId: 'a', requestId: 'three-argument-promise' }, {}, () => new Promise((resolve, reject) => {
    const socket = net.connect({ host: 'example.test', port: 9,
      lookup(host, options, callback) {
        return Promise.resolve(options.all ? [{ address: '127.0.0.1', family: 4 }] : { address: '127.0.0.1', family: 4 });
      } });
    const timeout = setTimeout(() => { socket.destroy(); reject(new Error('three argument Promise resolver did not report denial')); }, 250);
    socket.once('connect', () => { clearTimeout(timeout); socket.destroy(); reject(new Error('private connection allowed')); });
    socket.once('error', error => { clearTimeout(timeout); try { assert.ok(error instanceof agent.Blocked); resolve(); } catch (failure) { reject(failure); } });
  }));
});

test('three argument unsupported DNS resolver returns fail closed immediately', () => {
  agent.withRequest({ tenantId: 'a', requestId: 'unsupported-callback-return' }, {}, () => {
    assert.throws(() => net.connect({ host: 'example.test', port: 9,
      lookup(host, options, callback) { return '127.0.0.1'; } }),
    error => error instanceof agent.Blocked && error.event.reason === 'unsupported_lookup_form');
  });
});

test('DNS callback and Promise completion report only one checked denial', () => {
  // Stub only the TCP transport, so repeated resolver completion cannot open sockets.
  const probe = child.spawnSync(process.execPath, ['-e', `
    const assert = require('node:assert/strict'), net = require('node:net');
    const errors = [];
    net.Socket.prototype.connect = function(options) {
      options.lookup(options.host, { all: true }, error => errors.push(error));
      return this;
    };
    const agent = require('./index.cjs'); agent.install();
    agent.withRequest({ tenantId: 'a', requestId: 'duplicate' }, {}, scope => {
      const addresses = [{ address: '127.0.0.1', family: 4 }];
      const socket = net.connect({ host: 'example.test', port: 9,
        lookup(host, options, callback) {
          callback(null, addresses); callback(null, addresses);
          return Promise.resolve(addresses);
        } });
      assert.ok(socket instanceof net.Socket);
      setImmediate(() => {
        assert.equal(scope.events.length, 1);
        assert.equal(errors.length, 1);
        assert.ok(errors[0] instanceof agent.Blocked);
      });
    });
  `], { cwd: __dirname, encoding: 'utf8' });
  assert.equal(probe.status, 0, probe.stderr);
});

test('empty Promise DNS arrays emit one socket error without unhandled rejection', () => {
  const probe = child.spawnSync(process.execPath, ['-e', `
    const assert = require('node:assert/strict'), net = require('node:net');
    const agent = require('./index.cjs'); agent.install();
    const unhandled = [];
    process.on('unhandledRejection', error => unhandled.push(error));
    (async () => {
      let errors = 0, connections = 0, denial;
      await agent.withRequest({ tenantId: 'a', requestId: 'empty-dns' }, {}, () => new Promise(resolve => {
        const socket = net.connect({ host: 'example.test', port: 9, lookup: () => Promise.resolve([]) });
        const timeout = setTimeout(() => { socket.destroy(); resolve(); }, 250);
        socket.on('connect', () => { connections++; socket.destroy(); });
        socket.on('error', error => {
          errors++; denial = error; clearTimeout(timeout); socket.destroy(); setImmediate(resolve);
        });
      }));
      await new Promise(resolve => setImmediate(resolve));
      assert.deepEqual(unhandled, [], 'empty resolution must not reject outside the socket');
      assert.equal(errors, 1, 'empty resolution must signal one socket error');
      assert.equal(connections, 0);
      assert.ok(denial instanceof agent.Blocked);
      assert.equal(denial.event.reason, 'unsupported_lookup_form');
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `], { cwd: __dirname, encoding: 'utf8', timeout: 2000 });
  assert.equal(probe.status, 0, probe.stderr);
});

test('Promise DNS rejections preserve resolver errors without policy denial', async () => {
  const failure = new Error('DNS resolver failed');
  let errors = 0, connections = 0;
  await agent.withRequest({ tenantId: 'a', requestId: 'rejected-dns' }, {}, scope => new Promise((resolve, reject) => {
    const socket = net.connect({ host: 'example.test', port: 9, lookup: () => Promise.reject(failure) });
    const timeout = setTimeout(() => { socket.destroy(); reject(new Error('DNS rejection did not reach the socket')); }, 250);
    socket.once('connect', () => { connections++; clearTimeout(timeout); socket.destroy(); reject(new Error('failed resolution connected')); });
    socket.on('error', error => {
      errors++; clearTimeout(timeout); socket.destroy();
      try { assert.equal(error, failure); assert.equal(scope.events.length, 0); setImmediate(resolve); }
      catch (assertion) { reject(assertion); }
    });
  }));
  assert.equal(errors, 1);
  assert.equal(connections, 0);
});

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
