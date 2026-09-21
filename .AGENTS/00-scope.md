# Scope

- New implementation lives under `gnx-node/`; do not modify the legacy runtime.
- Architecture authority: `NuevaPropuesta/arquitectura.md`.
- No localhost HTTP control plane. Setup ↔ host agent uses a named pipe.
- Do not embed runtime config, Quadlets, gateway rules, or secrets in Rust.
- Use only the approved model: `gpt-5.6-luna`, effort `medium`.
