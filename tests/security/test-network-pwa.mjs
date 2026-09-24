import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = async relative => readFile(join(root, relative), 'utf8');

const routes = await read('payload/node/gateway/routes.conf');
assert.match(routes, /https:\/\/app\.gnx[\s\S]*tls \/etc\/gnx\/ca\/gateway-cert\.pem \/etc\/gnx\/ca\/gateway-key\.pem/);
assert.match(routes, /https:\/\/compute\.gnx[\s\S]*reverse_proxy https:\/\/127\.0\.0\.1:8006/);
assert.match(routes, /tls_trust_pool file \/etc\/gnx\/ca\/backend-ca\.pem/);
assert.match(routes, /tls_server_name compute\.gnx/);
assert.doesNotMatch(routes, /tls_insecure_skip_verify|tls_server_name\s+127\.0\.0\.1/);
assert.match(routes, /protocols h1 h2/);
assert.doesNotMatch(routes, /protocols[^\n]*h3/);
assert.equal((routes.match(/Alt-Svc "clear"/g) ?? []).length, 2);
assert.match(routes, /@status path \/status\.json/);
assert.match(routes, /header @status Cache-Control "no-store"/);

const ingress = await read('payload/node/network/ingress.nft');
assert.match(ingress, /policy drop/);
assert.match(ingress, /^\s*ct state established,related accept\s*$/m);
assert.match(ingress, /iifname "lo" accept/);
assert.match(ingress, /iifname "tailscale0" udp dport 5353 accept/);
assert.match(ingress, /iifname "tailscale0" tcp dport 5353 accept/);
assert.match(ingress, /iifname "tailscale0" tcp dport 443 accept/);
assert.doesNotMatch(ingress, /dport 8006/);

const acceptRules = ingress.split(/\r?\n/).map(line => line.trim()).filter(line => line.endsWith('accept'));
assert.deepEqual(acceptRules.filter(rule => rule.includes('ct state')), ['ct state established,related accept']);
for (const rule of acceptRules.filter(rule => !rule.includes('ct state'))) {
  assert.match(rule, /^(?:iifname "(?:lo|tailscale0)"(?: (?:udp|tcp) dport (?:443|5353))?|iifname "eth0" ip saddr 172\.16\.0\.0\/12 tcp dport 443) accept$/,
    `new inbound accept rule is not limited to approved local/tailnet sources: ${rule}`);
}

const webFiles = ['index.html', 'app.js', 'sw.js', 'manifest.webmanifest'];
const web = await Promise.all(webFiles.map(file => read(`apps/web-app/${file}`)));
const webText = web.join('\n');
assert.doesNotMatch(webText, /127\.0\.0\.1|localhost|pipe|localStorage|sessionStorage|Authorization/i);
assert.match(web[0], /Content-Security-Policy/);
assert.match(web[1], /protocol === 'https:'/);
assert.match(web[1], /hostname === 'app\.gnx'/);
assert.match(web[1], /fetch\('\.\/status\.json', \{ cache: 'no-store' \}\)/);
assert.match(web[1], /window\.setInterval\(\(\) => void refreshStatus\(\), 15000\)/);
assert.match(web[1], /status\.state === 'NodeReady'/);
assert.match(web[2], /event\.request\.method !== 'GET'/);
assert.match(web[2], /url\.origin !== self\.location\.origin/);
assert.match(web[2], /cache\.addAll/);
assert.doesNotMatch(web[2], /compute\.gnx|Authorization|localStorage|sessionStorage/i);
assert.match(web[3], /"start_url":"\.\/"/);
assert.match(web[3], /"scope":"\.\/"/);

const app = web[1];
assert.match(app, /protocol === 'gnx:'/);
assert.match(app, /hostname === 'ui'/);
assert.match(app, /method: 'JoinMesh'/);
assert.match(app, /tailscale_auth_key: key\.value/);
assert.match(app, /proxmox_password: password\.value/);
assert.match(app, /key\.value = ''/);
assert.match(app, /password\.value = ''/);
assert.match(app, /if \(isTrustedLocalSetup && onboarding && onboardingForm\)/);
assert.match(await read('payload/node/install.run'), /--compute-secret-file/);
assert.match(await read('payload/node/install.run'), /PROXMOX_PASSWORD/);
const compute = await read('payload/node/services/compute.container');
assert.match(compute, /^EnvironmentFile=\/var\/lib\/gnx-node\/secrets\/compute\.env$/m);
assert.match(compute, /^PublishPort=127\.0\.0\.1:8006:8006$/m);
assert.doesNotMatch(compute, /^PublishPort=(?!127\.0\.0\.1:8006:8006)/m, 'compute must not publish 8006 publicly');
assert.doesNotMatch(compute, /^Network=host$/m, 'compute must not use host networking');
const runtimeInstall = await read('payload/node/install.run');
assert.doesNotMatch(runtimeInstall, /Environment=PROXMOX_PASSWORD=|Environment=TS_AUTHKEY=/);
assert.match(runtimeInstall, /mesh.*pending/);
assert.match(runtimeInstall, /private-ca\.cert\.pem/);
assert.match(runtimeInstall, /private-ca\.key\.pem/);

console.log('network/PWA static checks passed; live tailnet checks remain operator-gated');
