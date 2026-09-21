# GnX Node installer

Installer assets live with the product workspace. `scripts/build.ps1` builds both release executables, stages the local Setup UI, and invokes WiX from this directory.

Setup uses the Windows WebView2 desktop control. The Evergreen WebView2 Runtime must be installed on the machine before launching `gnx-setup.exe`; the installer does not download or bootstrap it. Install the runtime from Microsoft on offline/provisioned images, then launch Setup from the installed directory.
