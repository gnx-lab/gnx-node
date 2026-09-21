# Integration contract

- State source: `%ProgramData%\GnX\Node\state\`.
- IPC operations: GetProgress, Provision, JoinMesh, Retry, Cancel, Deprovision.
- Runtime commands: `install.run check|install`, then `verify.run`.
- Runtime emits sanitized JSON Lines to stdout and nonzero exit codes on failure.
- Image references are fixed by digest in their respective Quadlets.
- NODE_READY requires all four services plus local verification; external CA/Split-DNS is ACTION_REQUIRED.
