# GnX Node Linux runtime

`install.run` is the idempotent Linux bootstrap contract. It requires root,
systemd, `/dev/net/tun`, `/dev/kvm`, nftables, curl, OpenSSL, and Podman (or a
supported package manager). TUN and KVM are separate capabilities: Tailscale
uses TUN, while compute uses KVM.

Run the preflight, then install the payload and consume `verify.run` as the
canonical sanitized JSONL readiness result:

```sh
bash ./install.run check --payload-dir /opt/gnx/payload/node --state-dir /var/lib/gnx/state
bash ./install.run install --payload-dir /opt/gnx/payload/node --state-dir /var/lib/gnx/state \
  --mesh-secret-file /run/gnx-node/enrollment.env \
  --compute-secret-file /run/gnx-node/proxmox.env
/var/lib/gnx-node/verify.run --state-dir /var/lib/gnx/state
```

The two input files are root-owned, regular files with mode `0400` or `0600`:

`enrollment.env` contains only `TS_AUTHKEY=tskey-auth-...`; `proxmox.env`
contains only `PROXMOX_PASSWORD=...`.

The Windows host's one-shot files use the service-owned
`<state-dir>/staging/{mesh,compute}-<request-id>.env` names and inherit its
SYSTEM/Administrators ACL; WSL drvfs mode bits are therefore not used as the
trust decision for those exact names. All other caller-supplied paths must be
Unix root-owned and mode `0400`/`0600`.

The values are never accepted as arguments or emitted in logs/JSONL. The mesh
file is staged only in `/run/gnx-node` (tmpfs), consumed by the Tailscale
Quadlet, and removed on success, retry, cancellation, or process exit. The
Proxmox file is atomically copied to `/var/lib/gnx-node/secrets/compute.env`
with mode `0600` so the compute service can resume after reboot; only this
protected path is referenced by its Quadlet. Repeating install replaces units
and web assets while preserving service state, protected Proxmox credentials,
and operator-managed CA material.

Install consumes the host-created product CA at
`<state-dir>/ca/private-ca.{cert,key}.pem` when present (and refuses a partial
pair), or creates one only for direct Linux use. It also creates a separate
backend CA when needed, then creates SAN certificates for `app.gnx`,
`compute.gnx`, and the internal Proxmox endpoint. Caddy serves the gateway
certificate and validates `compute.gnx:8006` with `backend-ca.pem`; no insecure
TLS fallback is enabled. The host never publishes port `8006`.

The four Quadlets are `mesh`, `dns`, `gateway`, and `compute`, orchestrated by
`platform.target`. Pi-hole listens on host DNS ports while its web UI is moved
to `8082`, leaving host HTTPS/443 exclusively to Caddy; the host writes the
`app.gnx` and `compute.gnx` dnsmasq records only after mesh authentication.
Mesh enrollment is accepted only after Tailscale reports an online identity and
a tailnet address. `verify.run` checks KVM/TUN, service
liveness, pinned images, nftables, DNS, both CA chains, and all three HTTPS
endpoints. Its JSONL includes sanitized `tailscale_ip` and `pihole_ip` fields and
the required operator actions: configure Split DNS for `gnx` to the reported
Tailscale address and trust the gateway CA on authorized tailnet clients.

The remote `https://app.gnx` PWA has no bridge or control privilege. The same
static assets show credential onboarding only under the trusted `gnx://ui`
WebView origin; credentials are posted to the allowlisted local `JoinMesh`
bridge and cleared immediately. The service worker caches only immutable app
assets, never compute responses, authentication data, or secrets.

Host-only acceptance gates are Podman image pull/start, KVM and TUN access,
systemd activation, Split DNS, client CA trust, and live HTTPS health checks.
Missing KVM must remain `kvm:fail`; no simulated service counts as readiness.
