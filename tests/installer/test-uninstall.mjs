import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Deliberately compact: one static contract covers the MSI, Burn delegation,
// and the intentionally limited uninstall boundary without mutating a host.
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = relative => readFile(join(root, relative), 'utf8');

const [product, bundle, readme] = await Promise.all([
  read('installer/Product.wxs'),
  read('installer/bundle/Bundle.wxs'),
  read('installer/README.md'),
]);

// MSI owns only the Windows package: service lifecycle plus installed payload.
assert.match(product, /ServiceInstall[^>]*Name="GnXHostAgent"[^>]*Start="auto"/);
assert.match(product, /ServiceControl[^>]*Name="GnXHostAgent"[^>]*Stop="both"[^>]*Remove="uninstall"/);
assert.match(product, /ComponentGroup Id="HostPayloadFiles"/);
assert.match(product, /ComponentGroup Id="NodePayloadFiles"/);
assert.doesNotMatch(product, /ProgramData|CustomAction|RemoveFile/i, 'MSI must not own runtime state cleanup');

// Burn must remain a thin wrapper over that same MSI, including uninstall.
assert.match(bundle, /<MsiPackage\s+SourceFile="\$\(var\.MsiPackage\)"/);
assert.doesNotMatch(bundle, /Deprovision|CustomAction|ExeCommand/i);

// The boundary is explicit, including sensitive residual state and network
// leftovers, so a future cleanup change cannot silently become misleading.
for (const term of [
  'WSL node',
  'runtime data',
  'private CA',
  'hosts',
  'port-proxy',
  'credentials',
]) assert.match(readme, new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'), `README must document ${term}`);
assert.match(readme, /no fake `Deprovision`\s+action/i);

// One operator-level smoke checklist is enough for this stage; it must not
// imply that uninstall removes the Linux runtime.
assert.match(readme, /Minimal uninstall acceptance checklist/);
assert.match(readme, /Reinstallation contract/);
for (const check of [
  'GnXHostAgent.*absent',
  'installed Windows files.*absent',
  'WSL.*retained',
  'state.*retained',
  'hosts.*port-proxy.*retained',
]) assert.match(readme, new RegExp(check, 'i'), `missing uninstall check: ${check}`);

const linuxNode = await read('apps/host-agent/src/linux_node.rs');
assert.match(linuxNode, /if !distro_is_registered\(\)/);
assert.match(linuxNode, /materialize_payload\(&node_root\)/);

console.log('installer uninstall contract checks passed');
