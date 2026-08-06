# PerfLens known issues

[简体中文](known-issues.zh-CN.md) | English

This document records reproduced issues and their bounded workarounds, including
resolved issues. Do not weaken deployment safety checks to work around them.

## KI-2026-08-06: native DEB upgrade can retain stale Python bytecode

- Affected path: an in-place native DEB upgrade from `v0.1.2` to `v0.1.3`.
- Fix status: fixed on the development branch for the next release.
- Symptom: `dpkg-query` reports `0.1.3-1` while a PerfLens entry point still reports `0.1.2`.
- Cause: reproducible packages fix Python source mtimes, allowing an old same-path `.pyc` to remain
  timestamp/size-valid when the older package did not remove it during configure.

The development fix makes the native launcher ignore inline package caches and disables bytecode
writes before importing PerfLens. The main package `postinst` also removes only legacy `.pyc/.pyo`
files and empty cache directories below fixed `/usr/lib/perflens` during `configure`.

Affected `v0.1.3` systems can use this bounded workaround:

```bash
dpkg-query -W -f='${Package} ${Version}\n' perflens perflens-collector
sudo find /usr/lib/perflens -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
sudo find /usr/lib/perflens -depth -type d -name '__pycache__' -empty -delete
hash -r
perflens --version
```

Do not delete the whole `/usr/lib/perflens` package runtime.

## KI-2026-08-05: `umask 0002` makes staged Collector policy undeployable

- Affected version: `v0.1.2`.
- Fixed in: `v0.1.3`.
- Status: resolved; the bounded workaround remains valid for `v0.1.2`.
- Scope: a new `collector.toml` produced by `perflens init --prepare-collector`
  or `perflens setup --prepare-collector`.
- Not affected: a policy already installed at `/etc/perflens/collector.toml`,
  existing-profile analysis, and read-only use without the Collector.

### Symptom and cause

On a host with `umask 0002`, the generated policy can have mode `0664`.
`perflens-admin deploy --dry-run` then correctly fails with
`PATH_SAFETY_VIOLATION` because the policy is group-writable. The `v0.1.2`
asset generator relies on the process umask instead of explicitly setting the
final policy mode. The deployer's ownership, type, size, and non-writable checks
must not be weakened.

### `v0.1.3` fix

The staging directory is now explicitly `0700`, `collector.toml` is `0600`, and
the systemd/sysusers templates are `0644`, independent of the caller's umask.
All deployer safety checks remain in place. After upgrading, run
`perflens init --update --prepare-collector` to regenerate assets; an unchanged
v0.1.2 Skill is also safely migrated to the shorter `perflens` directory name.

### `v0.1.2` workaround

Run as the ordinary user who generated the configuration:

```bash
chmod 600 "$PWD/perflens-setup/collector-assets/collector.toml"
stat -c '%a %U:%G %n' \
  "$PWD/perflens-setup/collector-assets/collector.toml"

perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml" \
  --dry-run

sudo perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml"
```

Confirm mode `600` before deployment. Do not use `sudo` to bypass the mode
correction. This is a one-time host deployment for the authorized Linux user;
other projects only need their project-level `perflens init`.

### Fix acceptance

`v0.1.3` explicitly sets staged `collector.toml` to `0600`, tests generation
under `umask 0002` and `0000`, proves that the unmodified generated policy passes
deployment validation, and preserves every current deployer safety check.
