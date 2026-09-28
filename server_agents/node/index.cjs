'use strict';
const { AsyncLocalStorage } = require('node:async_hooks');
const fs = require('node:fs');
const path = require('node:path');
const dns = require('node:dns');
const net = require('node:net');
const child = require('node:child_process');
const { fileURLToPath } = require('node:url');
const { syncBuiltinESMExports } = require('node:module');

const context = new AsyncLocalStorage();
const realpath = fs.realpathSync.bind(fs);
const exists = fs.existsSync.bind(fs);
const connect = net.Socket.prototype.connect;
const originalLookup = dns.lookup.bind(dns);
let installed = false;
const sqlClients = new WeakSet();
const restricted = new net.BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) restricted.addSubnet(address, prefix, 'ipv4');
restricted.addSubnet('2001::', 23, 'ipv6');
restricted.addSubnet('2001:db8::', 32, 'ipv6');
restricted.addSubnet('2002::', 16, 'ipv6');
const publicV6 = new net.BlockList();
publicV6.addSubnet('2000::', 3, 'ipv6');

class Blocked extends Error {
  constructor(event) { super(`RASP blocked ${event.sink}: ${event.reason}`); this.event = event; this.code = 'RASP_BLOCKED'; }
}

function block(scope, sink, reason) {
  const event = Object.freeze({ tenantId: scope.tenantId, requestId: scope.requestId, sink, reason });
  if (scope.events.length === 100) scope.events.shift();
  scope.events.push(event);
  throw new Blocked(event);
}

function patch(scope, sink) {
  if (scope.policy.deniedSinks.includes(sink)) block(scope, sink, 'virtual_patch');
}

function canonical(value) {
  const input = value instanceof URL ? fileURLToPath(value) : Buffer.isBuffer(value) ? value.toString() : value;
  if (typeof input !== 'string') throw new TypeError('path must be a string');
  let current = path.resolve(input);
  const suffix = [];
  while (!exists(current)) {
    const parent = path.dirname(current);
    if (parent === current) throw new Error('path has no existing ancestor');
    suffix.unshift(path.basename(current)); current = parent;
  }
  return path.join(realpath(current), ...suffix);
}

function withRequest(identity, policy, operation) {
  if (typeof identity.tenantId !== 'string' || !identity.tenantId.trim() ||
      typeof identity.requestId !== 'string' || !identity.requestId.trim()) throw new TypeError('request identity required');
  const sources = identity.sources || [];
  if (!Array.isArray(sources) || sources.length > 256 || sources.some(value => typeof value !== 'string' || value.length > 8192)) {
    throw new TypeError('invalid request sources');
  }
  const policyPath = value => {
    if (typeof value !== 'string' || !path.isAbsolute(value)) throw new TypeError('policy paths must be absolute');
    return canonical(value);
  };
  const allowedRoots = (policy.allowedRoots || []).map(policyPath);
  const allowedExecutables = (policy.allowedExecutables || []).map(policyPath);
  const allowedAddresses = policy.allowedAddresses || [];
  if (allowedAddresses.some(address => net.isIP(address) === 0)) throw new TypeError('allowed addresses must be literal IPs');
  const scope = { tenantId: identity.tenantId, requestId: identity.requestId,
    sources: [...sources.filter(value => value.length > 0)], events: [],
    policy: Object.freeze({ allowedRoots, allowedExecutables, allowedAddresses: [...allowedAddresses], deniedSinks: [...(policy.deniedSinks || [])] }) };
  return context.run(scope, () => operation(scope));
}

function checkPath(value) {
  const scope = context.getStore();
  if (!scope) return;
  patch(scope, 'file');
  if (typeof value === 'number') return;
  const target = canonical(value);
  if (!scope.policy.allowedRoots.some(root => {
    const relative = path.relative(root, target);
    return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith('..' + path.sep));
  })) block(scope, 'file', 'outside_allowed_roots');
}

function checkProcess(executable) {
  const scope = context.getStore();
  if (!scope) return;
  patch(scope, 'process');
  if (typeof executable !== 'string' || !path.isAbsolute(executable) ||
      !scope.policy.allowedExecutables.includes(canonical(executable))) block(scope, 'process', 'executable_not_allowed');
}

function checkAddress(scope, address) {
  patch(scope, 'network');
  if (scope.policy.allowedAddresses.includes(address)) return;
  const family = net.isIP(address);
  if (family === 0 || restricted.check(address, family === 6 ? 'ipv6' : 'ipv4') ||
      (family === 6 && !publicV6.check(address, 'ipv6'))) block(scope, 'network', 'nonpublic_address');
}

function checkSql(statement) {
  const scope = context.getStore();
  if (!scope) return;
  patch(scope, 'sql');
  if (typeof statement !== 'string') throw new TypeError('SQL text required');
  if (scope.sources.some(source => statement.includes(source))) block(scope, 'sql', 'request_value_in_statement');
}

function protectSqlClient(client) {
  if (sqlClients.has(client)) return client;
  if (typeof client.query !== 'function') throw new TypeError('SQL client.query required');
  const query = client.query;
  client.query = function(statement, ...args) {
    checkSql(typeof statement === 'object' && statement !== null ? statement.text : statement);
    return query.call(this, statement, ...args);
  };
  sqlClients.add(client);
  return client;
}

function install() {
  if (installed) return;
  for (const name of ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'open', 'openSync', 'createReadStream', 'createWriteStream']) {
    const original = fs[name];
    fs[name] = function(file, ...args) { checkPath(file); return original.call(this, file, ...args); };
  }
  for (const name of ['readFile', 'writeFile', 'appendFile', 'open']) {
    const original = fs.promises[name];
    fs.promises[name] = async function(file, ...args) { checkPath(file); return original.call(this, file, ...args); };
  }
  for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync']) {
    const original = child[name];
    child[name] = function(executable, ...args) {
      checkProcess(executable);
      const scope = context.getStore();
      if (scope && args.some(value => value && !Array.isArray(value) && typeof value === 'object' && value.shell)) block(scope, 'process', 'shell_execution');
      return original.call(this, executable, ...args);
    };
  }
  for (const name of ['exec', 'execSync']) {
    const original = child[name];
    child[name] = function(...args) {
      const scope = context.getStore();
      if (scope) block(scope, 'process', 'shell_execution');
      return original.apply(this, args);
    };
  }
  net.Socket.prototype.connect = function(...args) {
    const scope = context.getStore();
    if (!scope) return connect.apply(this, args);
    // net.connect forwards its normalized [options, callback] tuple to Socket.connect.
    if (args.length === 1 && Array.isArray(args[0])) args = args[0];
    patch(scope, 'network');
    let options;
    if (typeof args[0] === 'object' && args[0] !== null && !Array.isArray(args[0])) options = { ...args[0] };
    else if (typeof args[0] === 'number') options = { port: args[0], host: typeof args[1] === 'string' ? args[1] : 'localhost' };
    else block(scope, 'network', 'unsupported_connect_form');
    if (options.path) block(scope, 'network', 'unix_socket');
    const host = options.host || 'localhost';
    if (net.isIP(host)) checkAddress(scope, host);
    else {
      const lookup = options.lookup || originalLookup;
      options.lookup = (hostname, lookupOptions, callback) => lookup(hostname, lookupOptions, (error, addresses, family) => {
        if (error) { callback(error); return; }
        try {
          for (const address of Array.isArray(addresses) ? addresses.map(item => item.address) : [addresses]) checkAddress(scope, address);
        } catch (denied) { callback(denied); return; }
        callback(null, addresses, family);
      });
    }
    const callback = typeof args.at(-1) === 'function' ? args.at(-1) : undefined;
    return callback ? connect.call(this, options, callback) : connect.call(this, options);
  };
  syncBuiltinESMExports();
  installed = true;
}

module.exports = { install, withRequest, checkSql, protectSqlClient, Blocked };
