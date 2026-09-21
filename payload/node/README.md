# GnX Node Linux runtime

`install.run` is the idempotent Linux bootstrap contract. It requires root,
systemd, `/dev/net/tun`, `/dev/kvm`, nftables, curl, and a Podman package
manager when Podman is not already installed. TUN and KVM are checked as
separate capabilities: TUN is for the private mesh, while KVM is for compute.

Run the preflight, then install the payload and consume `verify.run` as the
canonical JSONL readiness result:

```sh
bash ./install.run check --payload-dir /opt/gnx/payload/node --state-dir /var/lib/gnx/state
bash ./install.run install --payload-dir /opt/gnx/payload/node --state-dir /var/lib/gnx/state
/var/lib/gnx-node/verify.run --state-dir /var/lib/gnx/state
```

For first enrollment, pass a protected root-owned file containing exactly an
`TS_AUTHKEY=...` EnvironmentFile entry. The path is not the secret value:

```sh
bash ./install.run install \
  --payload-dir /opt/gnx/payload/node \
  --state-dir /var/lib/gnx/state \
  --mesh-secret-file /run/gnx-node/enrollment.env
```

The file is staged only in `/run/gnx-node` (tmpfs) and removed after
`mesh.service` reports an authenticated, online Tailscale identity with a
tailnet address; systemd being active alone is not sufficient. Persistent mesh
state contains the resulting identity, not the enrollment key. Secret values
never appear in arguments, logs, or JSONL output. Repeating install preserves
persistent service data and the operator-managed backend CA while replacing
only the payload units and the read-only web assets.

The four Quadlets are `mesh`, `dns`, `gateway`, and `compute`, orchestrated by
`platform.target`. Each image is pinned to one immutable OCI digest. Compute
is the release's sealed Proxmox image, uses `/dev/kvm`, serves HTTPS on its
internal `:8006`, and is not published as a host port; nftables permits only
loopback and the private mesh ingress. The gateway validates the backend CA
for `compute.gnx` and never enables insecure TLS.

The CA files are separate operator-managed inputs: `gateway-ca.pem` validates
the gateway certificates for `app.gnx:443` and `compute.gnx:443`, while
`backend-ca.pem` validates only the internal Proxmox endpoint
`compute.gnx:8006`. `verify.run` checks all three HTTPS endpoints with their
corresponding CA and rejects missing or mismatched trust.

The real-host gates that cannot be proven by static tests are Podman image
pull/start, KVM device access, TUN access, systemd activation, Split DNS,
backend CA trust, and the HTTPS health checks. A host with missing KVM must
remain `kvm:fail`; no simulated service counts as acceptance.
