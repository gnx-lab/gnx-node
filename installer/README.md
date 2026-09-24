# GnX Node installer

Installer assets live with the product workspace. `scripts/build.ps1` builds both release executables, stages the local Setup UI, the host payload, and the node payload (including the PWA), then invokes WiX from this directory.

The MSI is the package boundary: it copies files and registers `GnXHostAgent`; it does not run Linux provisioning. `bundle/Bundle.wixproj` is the Burn bootstrapper boundary and refuses to continue when the Evergreen WebView2 Runtime registry marker is absent. Build the MSI first, then the bundle:

```powershell
./installer/scripts/build.ps1
./installer/scripts/verify.ps1
```

The deterministic final artifacts are `build/installer/en-us/GnxNode.msi` and
`build/installer/GnxNodeSetup.exe`; the verification script checks both files,
their non-zero sizes, and SHA-256 hashes. To compile Burn independently after
an MSI build, run `dotnet build installer/bundle/Bundle.wixproj -p:Configuration=release`.

Setup uses the Windows WebView2 desktop control. The Evergreen WebView2 Runtime must be installed on the machine before launching `gnx-setup.exe`; Burn detects the runtime but does not download or bootstrap it. Install the runtime from Microsoft on offline/provisioned images, then launch Setup from the installed directory.

Onboarding credentials are accepted only by the five allowlisted control
operations. Setup writes a one-shot bundle under the interactive user's
temporary directory and sends only its bounded path over the administrator-only
named pipe; the host consumes and unlinks the bundle and stages separate
`TS_AUTHKEY`/`PROXMOX_PASSWORD` files for the fixed `install.run` contract.
Neither value is placed in argv, progress, logs, or durable state. The host
creates the product private CA under its protected state directory and reports
only the public certificate path plus explicit Split DNS and CA-trust actions.

## Uninstallation boundary

Uninstalling the MSI is intentionally a small, achievable package operation: it stops
and removes `GnXHostAgent` and deletes the installed Setup/payload files. It does not
pretend to tear down the already-provisioned WSL node, runtime data, private CA,
`hosts` entries, or port-proxy rules. Setup therefore exposes no fake `Deprovision`
action. Full runtime teardown is a separate future operation and must be implemented
and tested as a complete cleanup mission before it is offered.

### Minimal uninstall acceptance checklist

This is a short operator smoke check, not a second cleanup implementation:

- `GnXHostAgent` is absent after uninstall.
- Installed Windows files under `GnX Node` are absent.
- The WSL node and Linux runtime are retained.
- Product state, CA material, and credentials are retained and must be removed or rotated manually when required.
- `hosts` entries and port-proxy rules are retained and must be removed manually if the operator no longer wants the names routed locally.

## Reinstallation contract

A later MSI reinstall is expected to reuse the retained `gnx-node` distro, the
managed `gnxnodesvc` identity, and product state. The host verifies the sealed
payload and refreshes the runtime payload; it imports the distro only when it is
not already registered. Do not remove the WSL path, identity, CA, or state
between uninstall and reinstall if preserving the node is intended.

The WSL image contract is a sealed `payload/host/gnx-node-rootfs.tar` paired
with `payload/host/gnx-node-rootfs.tar.sha256` containing
`<lowercase sha256>  gnx-node-rootfs.tar`. The host verifies this digest before
registering only the fixed `gnx-node` distro, then requires its `gnxnodesvc`
identity and sealed payload marker before it can invoke `install.run`.

The checked-in release image is an Ubuntu Base 24.04.3 amd64 derivative. Its
official source is
`https://cdimage.ubuntu.com/ubuntu-base/releases/24.04.3/release/ubuntu-base-24.04.3-base-amd64.tar.gz`,
with the published checksum listing at
`https://cdimage.ubuntu.com/ubuntu-base/releases/24.04.3/release/SHA256SUMS`.
The source archive's official SHA-256 is
`6bc2cde3930ad088b3bb46fa45279e96d25bc3810f209850ecbe4722711874f9`.
Ubuntu and Canonical trademark/licensing information is published at
`https://ubuntu.com/legal/intellectual-property-policy`; files and packages
retain their upstream copyright and license notices.

The release input is `payload/host/gnx-node-rootfs.tar`, a gzip-compressed tar
accepted by `wsl --import`, with 37,744,448 bytes and SHA-256
`5215c762cd1562b9b6836b01f6e1a2207cee7bae0ee334e50316af72b9a871af`. Its
manifest is checked in beside it and is packaged into the MSI with the image.
Build and verification reject a missing artifact, malformed/non-lowercase
manifest, unexpected release digest, or content mismatch.

To reproduce the preparation (in an amd64 Ubuntu build environment), download
the URL above, verify the official checksum, extract it into an empty rootfs,
and install only the required boot/runtime packages:

```sh
curl -fLO https://cdimage.ubuntu.com/ubuntu-base/releases/24.04.3/release/ubuntu-base-24.04.3-base-amd64.tar.gz
printf '%s  %s\n' '6bc2cde3930ad088b3bb46fa45279e96d25bc3810f209850ecbe4722711874f9' ubuntu-base-24.04.3-base-amd64.tar.gz | sha256sum -c -
mkdir rootfs
tar --numeric-owner -xzf ubuntu-base-24.04.3-base-amd64.tar.gz -C rootfs
mount --bind /dev rootfs/dev
mount --bind /dev/pts rootfs/dev/pts
chroot rootfs env DEBIAN_FRONTEND=noninteractive apt-get update
chroot rootfs env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates
printf '[boot]\nsystemd=true\n' > rootfs/etc/wsl.conf
chroot rootfs apt-get clean
rm -rf rootfs/var/lib/apt/lists/*
tar --sort=name --numeric-owner --owner=0 --group=0 --mtime='UTC 1970-01-01' -C rootfs -cf - . | gzip -n > payload/host/gnx-node-rootfs.tar
sha256sum payload/host/gnx-node-rootfs.tar > payload/host/gnx-node-rootfs.tar.sha256
```

The final digest must equal the recorded release digest above; do not replace
the checked-in bytes or manifest with an unreviewed rebuild. The build command
validates and copies both host-payload inputs, and `scripts/verify.ps1`
revalidates the same contract before reporting MSI/Burn hashes.
