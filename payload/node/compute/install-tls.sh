#!/usr/bin/env bash
# Install the product backend certificate where Proxmox pveproxy reads it.
set -Eeuo pipefail

source_cert=/etc/gnx/ca/backend-cert.pem
source_key=/etc/gnx/ca/backend-key.pem
source_ca=/etc/gnx/ca/backend-ca.pem
target_dir=/etc/pve/local

[[ -s "$source_cert" && -s "$source_key" && -s "$source_ca" ]] || exit 1
for _ in {1..60}; do
  [[ -d "$target_dir" ]] && break
  sleep 1
done
[[ -d "$target_dir" ]] || exit 1

# /etc/pve is pmxcfs, not a normal filesystem: writes are supported but chmod,
# chown and atomic rename may return EPERM.  Let pmxcfs enforce its fixed file
# metadata and replace only the content expected by pveproxy.
cat "$source_cert" "$source_ca" > "$target_dir/pveproxy-ssl.pem"
cat "$source_key" > "$target_dir/pveproxy-ssl.key"
[[ -s "$target_dir/pveproxy-ssl.pem" && -s "$target_dir/pveproxy-ssl.key" ]] || exit 1
chown root:www-data "$target_dir/pveproxy-ssl.pem" "$target_dir/pveproxy-ssl.key" 2>/dev/null || true
chmod 0640 "$target_dir/pveproxy-ssl.pem" 2>/dev/null || true
chmod 0600 "$target_dir/pveproxy-ssl.key" 2>/dev/null || true
