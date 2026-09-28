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
const lstat = fs.lstatSync.bind(fs);
const readlink = fs.readlinkSync.bind(fs);
const readdir = fs.readdirSync.bind(fs);
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
  // Resolve each component in kernel order, including dangling link targets.
  let current = path.parse(process.cwd()).root;
  let components = (path.isAbsolute(input) ? input : process.cwd() + path.sep + input).split(path.sep);
  let links = 0;
  while (components.length) {
    const component = components.shift();
    if (!component || component === '.') continue;
    if (component === '..') { current = path.dirname(current); continue; }
    const candidate = path.join(current, component);
    let metadata;
    try { metadata = lstat(candidate); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (metadata?.isSymbolicLink()) {
      if (++links > 40) { const error = new Error('too many symbolic links'); error.code = 'ELOOP'; throw error; }
      const target = readlink(candidate);
      if (path.isAbsolute(target)) current = path.parse(target).root;
      components = target.split(path.sep).concat(components);
    } else current = candidate;
  }
  return current;
}

function unmappedAddress(address) {
  if (net.isIP(address) !== 6) return address;
  const normalized = new URL('http://[' + address.split('%')[0] + ']/').hostname.slice(1, -1);
  const match = /^::ffff:([a-f0-9]+):([a-f0-9]+)$/i.exec(normalized);
  if (!match) return address;
  const high = parseInt(match[1], 16), low = parseInt(match[2], 16);
  return [high >>> 8, high & 255, low >>> 8, low & 255].join('.');
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
  address = unmappedAddress(address);
  if (scope.policy.allowedAddresses.some(allowed => unmappedAddress(allowed) === address)) return;
  const family = net.isIP(address);
  if (family === 0 || restricted.check(address, family === 6 ? 'ipv6' : 'ipv4') ||
      (family === 6 && !publicV6.check(address, 'ipv6'))) block(scope, 'network', 'nonpublic_address');
}

function checkSql(statement) {
  const scope = context.getStore();
  if (!scope) return;
  patch(scope, 'sql');
  if (typeof statement !== 'string') throw new TypeError('SQL text required');
  if (scope.sources.some(source => sourceChangesSql(statement, source))) block(scope, 'sql', 'request_value_in_statement');
}

function sourceChangesSql(statement, source) {
  if (source.length < 3) return false;
  const tokens = [...statement.matchAll(/'(?:''|[^'])*'|"(?:""|[^"])*"|`(?:``|[^`])*`|\[[^\]]*\]|--[^\n]*|\/\*[\s\S]*?\*\/|[\p{L}\p{N}_$]+|[^\s]/gu)];
  for (let start = statement.indexOf(source); start !== -1; start = statement.indexOf(source, start + 1)) {
    const end = start + source.length;
    const overlaps = tokens.filter(token => token.index < end && token.index + token[0].length > start);
    if (overlaps.length > 1) return true;
    if (overlaps.length === 1) {
      const token = overlaps[0];
      if (!/^(?:['"`\[]|--|\/\*)/.test(token[0]) && token.index === start && token.index + token[0].length === end) return true;
    }
  }
  return false;
}

function preflightCopy(source, destination, options, ancestors = new Set()) {
  checkPath(source);
  checkPath(destination);
  const metadata = lstat(source);
  if (metadata.isSymbolicLink()) {
    const target = readlink(source);
    checkPath(path.isAbsolute(target) ? target : path.dirname(destination) + path.sep + target);
    if (!options?.dereference) return;
    source = canonical(source);
  }
  if (!lstat(source).isDirectory() || !options?.recursive) return;
  const resolved = canonical(source);
  if (ancestors.has(resolved)) block(context.getStore(), 'file', 'symlink_cycle');
  ancestors.add(resolved);
  try {
    for (const entry of readdir(source)) {
      preflightCopy(source + path.sep + entry, destination + path.sep + entry, options, ancestors);
    }
  } finally { ancestors.delete(resolved); }
}

function checkFileOperands(name, first, second, options) {
  if (!context.getStore()) return;
  if (name === 'cp' || name === 'cpSync') {
    const convert = value => value instanceof URL ? fileURLToPath(value) : Buffer.isBuffer(value) ? value.toString() : value;
    preflightCopy(convert(first), convert(second), options);
    return;
  }
  if (name.startsWith('symlink')) {
    checkPath(second);
    const target = Buffer.isBuffer(first) ? first.toString() : first;
    const link = second instanceof URL ? fileURLToPath(second) : Buffer.isBuffer(second) ? second.toString() : second;
    checkPath(path.isAbsolute(target) ? target : path.dirname(link) + path.sep + target);
  } else {
    checkPath(first);
    if (/^(rename|copyFile|cp|link)/.test(name)) checkPath(second);
  }
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
  const fileMethods = ['readFile', 'writeFile', 'appendFile', 'open', 'unlink', 'rm', 'rmdir', 'mkdir', 'rename', 'copyFile', 'cp', 'link', 'symlink', 'readdir', 'opendir', 'truncate', 'chmod', 'chown', 'utimes'];
  for (const name of [...fileMethods, ...fileMethods.map(name => name + 'Sync'), 'createReadStream', 'createWriteStream']) {
    const original = fs[name];
    if (typeof original !== 'function') continue;
    fs[name] = function(file, ...args) { checkFileOperands(name, file, args[0], args[1]); return original.call(this, file, ...args); };
  }
  for (const name of fileMethods) {
    const original = fs.promises[name];
    if (typeof original !== 'function') continue;
    fs.promises[name] = async function(file, ...args) { checkFileOperands(name, file, args[0], args[1]); return original.call(this, file, ...args); };
  }
  for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
    const original = child[name];
    child[name] = function(executable, ...args) {
      const forkOptions = name === 'fork' ? args.find(value => value && !Array.isArray(value) && typeof value === 'object') : null;
      checkProcess(name === 'fork' ? (forkOptions?.execPath || process.execPath) : executable);
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
