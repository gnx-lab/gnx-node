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
assert.match(mesh, /^Environment=TS_USERSPACE=false$/m);
const dns = await read('services/dns.container');
assert.match(dns, /^Environment=FTLCONF_dns_interface=tailscale0$/m);
assert.match(dns, /^Environment=FTLCONF_dns_port=5353$/m);
assert.match(dns, /^Environment=FTLCONF_dns_listeningMode=BIND$/m);
assert.match(dns, /^Environment=FTLCONF_webserver_port=8082$/m);
assert.match(dns, /^Environment=FTLCONF_misc_etc_dnsmasq_d=true$/m);
assert.match(dns, /\/var\/lib\/gnx-node\/dnsmasq\.d:\/etc\/dnsmasq\.d/);
assert.match(mesh, /^EnvironmentFile=\/run\/gnx-node\/mesh\.env$/m);
assert.match(mesh, /^WantedBy=multi-user\.target$/m);
assert.match(await read('install.run'), /podman exec gnx-mesh tailscale status --json/);
assert.match(await read('install.run'), /address=\/app\.gnx\//);
assert.match(await read('install.run'), /systemctl restart mesh\.service/);
assert.match(await read('install.run'), /install -y podman nftables curl dnsutils libc-bin python3 openssl kmod/);
assert.match(await read('install.run'), /require_podman_6\(\)/);
assert.match(await read('install.run'), /PODMAN_6_REQUIRED/);
assert.match(await read('install.run'), /modprobe kvm_amd/);
assert.match(await read('install.run'), /modprobe kvm_intel/);
assert.match(await read('install.run'), /wait_for_mesh_auth/);
assert.match(await read('install.run'), /wait_for_runtime_ready/);
assert.match(await read('install.run'), /for _ in \{1\.\.300\}/);
assert.doesNotMatch(await read('install.run'), /disable --now platform\.target/);
assert.match(await read('install.run'), /temporary mesh-auth race/);
assert.match(await read('install.run'), /--resolve app\.gnx:443:127\.0\.0\.1/);
assert.doesNotMatch(await read('install.run'), /listen-address=/);
assert.match(await read('install.run'), /address=\/compute\.gnx\/%s/);
assert.match(await read('install.run'), /modules-load\.d\/gnx-node-kvm\.conf/);
assert.match(await read('verify.run'), /podman exec gnx-mesh tailscale status --json/);
assert.match(await read('verify.run'), /BackendState.*Running/);
const compute = await read('services/compute.container');
assert.match(compute, /^AddDevice=\/dev\/kvm$/m);
assert.match(compute, /^AddDevice=\/dev\/fuse$/m);
assert.match(compute, /^HealthCmd=.*--cacert \/etc\/gnx\/ca\/backend-ca\.pem.*https:\/\/compute\.gnx:8006\/$/m);
assert.match(compute, /^HealthStartPeriod=5m$/m);
assert.match(compute, /^HealthOnFailure=kill$/m);
assert.match(compute, /^Notify=healthy$/m);
assert.match(compute, /^TimeoutStartSec=8min$/m);
assert.match(compute, /^TimeoutStopSec=2min$/m);
assert.doesNotMatch(compute, /^Network=host$/m);
assert.match(compute, /^PublishPort=127\.0\.0\.1:8006:8006$/m, 'compute must expose 8006 only on loopback');
assert.match(compute, /Image=.*(?:proxmox|dockurr).*@sha256:/i);
assert.match(compute, /\/var\/lib\/gnx-node\/compute:\/var\/lib\/vz/);
assert.match(compute, /\/var\/lib\/gnx-node\/compute-config:\/var\/lib\/pve-cluster/);
assert.match(compute, /gnx-install-tls\.sh/);
assert.match(compute, /--hostname=gnx-compute/);
assert.match(compute, /compute-config\/hostname:\/etc\/hostname/);
const tlsHook = await read('compute/install-tls.sh');
assert.match(tlsHook, /pveproxy-ssl\.pem/);
assert.match(tlsHook, /pveproxy-ssl\.key/);

const target = await read('services/platform.target');
for (const service of services) assert.match(target, new RegExp(`\\b${service}\\.service\\b`));
assert.match(target, /gnx-ingress\.service/);
const ingressService = await read('services/gnx-ingress.service');
assert.match(ingressService, /^ExecStart=\/usr\/sbin\/nft -f \/var\/lib\/gnx-node\/ingress\.nft$/m);
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
assert.match(routes, /protocols h1 h2/);
assert.doesNotMatch(routes, /protocols[^\n]*h3/);
assert.equal((routes.match(/Alt-Svc "clear"/g) ?? []).length, 2);

const ingress = await read('network/ingress.nft');
assert.match(ingress, /tailscale0/);
assert.match(ingress, /dport 53 redirect to :5353/);
assert.match(ingress, /iifname "tailscale0" udp dport 5353 accept/);
assert.match(ingress, /iifname "tailscale0" tcp dport 5353 accept/);
assert.doesNotMatch(ingress, /iifname "tailscale0" (?:udp|tcp) dport 53 accept/);
assert.doesNotMatch(ingress, /dport 8006/);

const verify = await read('verify.run');
for (const check of ['podman_6', 'tun', 'fuse', 'kvm', 'platform_target', 'mesh_authenticated', 'compute_https', 'app_https', 'compute_gateway_https']) assert.match(verify, new RegExp(`check ${check}`));
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

// Integration boundary: the host worker must invoke this exact runtime
// contract with protected files, while runtime output reuses host CA metadata.
const linuxNode = await readFile(join(root, 'apps', 'host-agent', 'src', 'linux_node.rs'), 'utf8');
assert.match(linuxNode, /"--mesh-secret-file"/);
const controlPipe = await readFile(join(root, 'apps', 'host-agent', 'src', 'control_pipe.rs'), 'utf8');
assert.match(controlPipe, /FlushFileBuffers/);
assert.match(linuxNode, /"--compute-secret-file"/);
assert.match(linuxNode, /install_with_secrets\(/);
assert.match(linuxNode, /pub fn reconcile_ingress[\s\S]*materialize_payload\(&node_root\)\?[\s\S]*\/opt\/gnx\/payload\/node\/web-app\/\.[\s\S]*\/var\/lib\/gnx-node\/web-app\/[\s\S]*nft[\s\S]*-f[\s\S]*\/var\/lib\/gnx-node\/ingress\.nft/);
assert.match(linuxNode, /pub fn runtime_checks[\s\S]*mesh_authenticated[\s\S]*compute_gateway_https[\s\S]*compute_https/);
assert.match(linuxNode, /reconcile_ingress[\s\S]*restart", "compute\.service[\s\S]*start", "platform\.target/);
const provisioning = await readFile(join(root, 'apps', 'host-agent', 'src', 'provisioning.rs'), 'utf8');
assert.match(provisioning, /linux_node::reconcile_ingress\(\)[\s\S]*linux_node::verify\(&state_dir\)/);
const hostMain = await readFile(join(root, 'apps', 'host-agent', 'src', 'main.rs'), 'utf8');
assert.match(hostMain, /state::refresh_app_status\(\)/);
assert.match(provisioning, /stage_runtime_file\(&path, "TS_AUTHKEY", &key\)/);
assert.match(provisioning, /stage_runtime_file\(&compute_path, "PROXMOX_PASSWORD", password\)/);
const ca = await readFile(join(root, 'apps', 'host-agent', 'src', 'ca.rs'), 'utf8');
assert.match(ca, /private-ca\.key\.pem/);
assert.match(ca, /private-ca\.cert\.pem/);
const install = await read('install.run');
assert.match(install, /state_dir\/ca\/private-ca\.cert\.pem/);
assert.match(install, /state_dir\/ca\/private-ca\.key\.pem/);
assert.match(install, /PRODUCT_CA_INCOMPLETE/);
assert.match(install, /mesh.*pending/);
assert.match(install, /PROXMOX_PASSWORD=\.\+\$/);
assert.match(install, /\$state_dir"\/staging\/mesh-\*\.env/);
assert.match(install, /: > \/run\/gnx-node\/mesh\.env/);
assert.ok(install.indexOf('flock -n 9') < install.indexOf('install -m 0600 /dev/null /run/gnx-node/mesh.env'));
assert.match(verify, /tailscale_ip/);
assert.match(verify, /pihole_ip/);
assert.match(verify, /next_actions/);
console.log('node-runtime static checks passed');
