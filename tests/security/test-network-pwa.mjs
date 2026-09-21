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

const ingress = await read('payload/node/network/ingress.nft');
assert.match(ingress, /policy drop/);
assert.match(ingress, /^\s*ct state established,related accept\s*$/m);
assert.match(ingress, /iifname "lo" accept/);
assert.match(ingress, /iifname "tailscale0" udp dport 53 accept/);
assert.match(ingress, /iifname "tailscale0" tcp dport 53 accept/);
assert.match(ingress, /iifname "tailscale0" tcp dport 443 accept/);
assert.doesNotMatch(ingress, /dport 8006/);

const acceptRules = ingress.split(/\r?\n/).map(line => line.trim()).filter(line => line.endsWith('accept'));
assert.deepEqual(acceptRules.filter(rule => rule.includes('ct state')), ['ct state established,related accept']);
for (const rule of acceptRules.filter(rule => !rule.includes('ct state'))) {
  assert.match(rule, /^iifname "(?:lo|tailscale0)"(?: (?:udp|tcp) dport (?:53|443))? accept$/,
    `new inbound accept rule is not limited to loopback/tailscale0: ${rule}`);
}

const webFiles = ['index.html', 'app.js', 'sw.js', 'manifest.webmanifest'];
const web = await Promise.all(webFiles.map(file => read(`apps/web-app/${file}`)));
const webText = web.join('\n');
assert.doesNotMatch(webText, /127\.0\.0\.1|localhost|pipe|localStorage|sessionStorage|Authorization/i);
assert.match(web[0], /Content-Security-Policy/);
assert.match(web[1], /protocol === 'https:'/);
assert.match(web[1], /hostname === 'app\.gnx'/);
assert.match(web[2], /event\.request\.method !== 'GET'/);
assert.match(web[2], /url\.origin !== self\.location\.origin/);
assert.match(web[2], /cache\.addAll/);
assert.doesNotMatch(web[2], /compute\.gnx|Authorization|localStorage|sessionStorage/i);
assert.match(web[3], /"start_url":"\.\/"/);
assert.match(web[3], /"scope":"\.\/"/);

console.log('network/PWA static checks passed; live tailnet checks remain operator-gated');
