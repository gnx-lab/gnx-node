// Fast local gate: run the compact installer, runtime, and security contracts
// together instead of starting three separate test cycles.
await import('./installer/test-uninstall.mjs');
await import('./node-runtime/test-runtime.mjs');
await import('./security/test-network-pwa.mjs');
