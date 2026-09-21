# Work tracking

## Agent host
- Owns: `gnx-node/apps/host-agent`, `gnx-node/apps/setup`, `gnx-node/crates`, `gnx-node/installer`, `gnx-node/payload/host`.
- Milestone: buildable Windows service and Setup UI skeleton; named-pipe contract; installer payload; tests.

## Agent node
- Owns: `gnx-node/apps/web-app`, `gnx-node/payload/node`, `gnx-node/tests/node-runtime`.
- Milestone: external runtime payload, PWA, Quadlets, canonical `verify.run`; tests.

## Integration
- Commit and push after each verified milestone.
- Do not change shared contract without an explicit coordinator message.
- Report tested commands, commit SHA, and remaining blocker.
