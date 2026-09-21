import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const payload = join(root, 'payload', 'node');
const read = file => readFile(join(payload, file), 'utf8');

const services = ['mesh', 'dns', 'gateway', 'compute'];
for (const service of services) {
  const text = await read(`services/${service}.container`);
  const images = text.match(/^Image=.*@sha256:[0-9a-f]{64}$/gm) ?? [];
  assert.equal(images.length, 1, `${service} must have one digest-pinned Image`);
  assert.doesNotMatch(text, /Image=.*:(latest|[0-9]+(?:\.[0-9]+)+)\s*$/m, `${service} has floating Image`);
  assert.match(text, /^Restart=always$/m);
}

const target = await read('services/platform.target');
for (const service of services) assert.match(target, new RegExp(`\\b${service}\\.service\\b`));

const routes = await read('gateway/routes.conf');
assert.match(routes, /https:\/\/app\.gnx/);
assert.match(routes, /https:\/\/compute\.gnx/);
assert.match(routes, /tls_trust_pool file/);
assert.doesNotMatch(routes, /tls_insecure_skip_verify/);

const ingress = await read('network/ingress.nft');
assert.match(ingress, /tailscale0/);
assert.doesNotMatch(ingress, /dport 8006/);

const verify = await read('verify.run');
for (const check of ['tun', 'kvm', 'platform_target', 'compute_https']) assert.match(verify, new RegExp(`check ${check}`));
const index = await readFile(join(root, 'apps', 'web-app', 'index.html'), 'utf8');
assert.doesNotMatch(index, /127\.0\.0\.1|localhost|pipe/i);
const sw = await readFile(join(root, 'apps', 'web-app', 'sw.js'), 'utf8');
assert.doesNotMatch(sw, /compute\.gnx|Authorization|localStorage/i);
console.log('node-runtime static checks passed');
