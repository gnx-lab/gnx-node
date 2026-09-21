# GnX Node Linux runtime

`install.run` is the external, idempotent bootstrap contract. Run `check` before `install`, then consume `verify.run` as the sole readiness result:

```sh
./install.run check --payload-dir /opt/gnx/payload/node --state-dir /var/lib/gnx/state
./install.run install --payload-dir /opt/gnx/payload/node --state-dir /var/lib/gnx/state
./verify.run --state-dir /var/lib/gnx/state
```

The agent supplies the temporary mesh credential by protected path; it is never an argument or persisted in this payload. Configure Split DNS for `gnx` and trust the managed backend CA as an operator action. The `compute` image is a release input and must be replaced with the approved release digest before distribution; the checked-in value is immutable and is not a floating tag.
