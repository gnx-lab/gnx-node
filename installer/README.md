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
