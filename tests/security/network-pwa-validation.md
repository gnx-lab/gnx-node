# Network/PWA validation

Run the reproducible checks from the repository root:

```sh
node tests/node-runtime/test-runtime.mjs
node tests/security/test-network-pwa.mjs
```

These checks validate the reviewed contracts: private hostnames, explicit gateway TLS files, backend CA validation for `compute.gnx`, no insecure TLS bypass, ingress restricted to loopback and `tailscale0`, protected secret-file inputs, local-only onboarding bridge access, and an asset-only offline cache with no credentials or privileged browser APIs.

The following require an authorized tailnet and cannot be proven by static tests:

- Configure Split DNS for `gnx` to the node’s Tailscale address, then resolve `app.gnx` and `compute.gnx` from a tailnet client.
- Install/trust the operator-managed gateway CA on that client and verify HTTPS certificate validation for both hostnames.
- From a tailnet client, verify the PWA loads, installs, and opens its cached shell after disconnecting; verify `compute.gnx` is never served from the PWA cache.
- Confirm a non-tailnet interface cannot reach DNS/HTTPS and that the compute service remains reachable only through the gateway.
- Confirm `install.run` retry/cancel/reboot cleanup leaves no mesh enrollment file in `/run/gnx-node`, while the protected Proxmox file remains mode `0600`.
- Confirm `verify.run` JSONL contains only sanitized Tailscale/Pi-hole addresses and the Split DNS plus gateway-CA next actions.
