import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const payload = join(root, 'payload', 'node');
const read = file => readFile(join(payload, file), 'utf8');

const services = ['mesh', 'dns', 'gateway', 'compute'];
for (const service of services) {
  const text = await read(`services/${service}.container`);
  const images = text.match(/^Image=.*@sha256:[0-9a-f]{64}$/gm) ?? [];
  assert.equal(images.length, 1, `${service} must have one digest-pinned Image`);
  assert.doesNotMatch(text, /registry\.gnx\.invalid|sha256:([0-9a-f])\1{63}/, `${service} has a placeholder image reference`);
  assert.doesNotMatch(text, /Image=.*:(latest|[0-9]+(?:\.[0-9]+)+)\s*$/m, `${service} has floating Image`);
  assert.match(text, /^Restart=always$/m);
}
assert.match(await read('services/mesh.container'), /^After=network-online\.target$/m);
for (const service of ['dns', 'gateway', 'compute']) {
  const text = await read(`services/${service}.container`);
  assert.match(text, /^Requires=mesh\.service/m, `${service} must depend on mesh`);
  assert.match(text, /^After=.*mesh\.service/m, `${service} must order after mesh`);
}
assert.match(await read('services/gateway.container'), /^Requires=mesh\.service dns\.service$/m);

const mesh = await read('services/mesh.container');
assert.match(mesh, /^AddDevice=\/dev\/net\/tun$/m);
assert.match(mesh, /^AddCapability=NET_ADMIN$/m);
assert.match(mesh, /^EnvironmentFile=-\/run\/gnx-node\/mesh\.env$/m);
assert.match(await read('install.run'), /podman exec gnx-mesh tailscale status --json/);
assert.match(await read('verify.run'), /podman exec gnx-mesh tailscale status --json/);
assert.match(await read('verify.run'), /BackendState.*Running/);
const compute = await read('services/compute.container');
assert.match(compute, /^AddDevice=\/dev\/kvm$/m);
assert.match(compute, /^Network=host$/m);
assert.doesNotMatch(compute, /^PublishPort=.*8006/m, 'compute must not publish 8006');
assert.match(compute, /Image=.*(?:proxmox|dockurr).*@sha256:/i);

const target = await read('services/platform.target');
for (const service of services) assert.match(target, new RegExp(`\\b${service}\\.service\\b`));
assert.match(target, /^Requires=.*mesh\.service.*dns\.service.*gateway\.service.*compute\.service/m);

for (const script of ['install.run', 'verify.run']) {
  const bashAvailable = spawnSync('bash', ['-c', 'true'], { encoding: 'utf8' }).status === 0;
  if (bashAvailable) {
    const result = spawnSync('bash', ['-n', join(payload, script)], { encoding: 'utf8' });
    assert.equal(result.status, 0, `${script} must pass bash -n: ${result.stderr}`);
  }
}

const routes = await read('gateway/routes.conf');
assert.match(routes, /https:\/\/app\.gnx/);
assert.match(routes, /https:\/\/compute\.gnx/);
assert.match(routes, /tls_trust_pool file/);
assert.doesNotMatch(routes, /tls_insecure_skip_verify/);

const ingress = await read('network/ingress.nft');
assert.match(ingress, /tailscale0/);
assert.doesNotMatch(ingress, /dport 8006/);

const verify = await read('verify.run');
for (const check of ['tun', 'kvm', 'platform_target', 'mesh_authenticated', 'compute_https', 'app_https', 'compute_gateway_https']) assert.match(verify, new RegExp(`check ${check}`));
assert.match(verify, /--resolve compute\.gnx:8006:127\.0\.0\.1/);
assert.match(verify, /gateway-ca\.pem/);
assert.match(verify, /backend-ca\.pem/);
assert.match(verify, /https:\/\/app\.gnx\//);
assert.match(verify, /https:\/\/compute\.gnx\//);
assert.doesNotMatch(verify, /tls_insecure_skip_verify|curl[^\n]*-k(?:\s|$)/);
const index = await readFile(join(root, 'apps', 'web-app', 'index.html'), 'utf8');
assert.doesNotMatch(index, /127\.0\.0\.1|localhost|pipe/i);
const sw = await readFile(join(root, 'apps', 'web-app', 'sw.js'), 'utf8');
assert.doesNotMatch(sw, /compute\.gnx|Authorization|localStorage/i);
console.log('node-runtime static checks passed');
