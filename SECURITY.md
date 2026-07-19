# Security policy

## Supported versions

Security fixes are provided for the latest `1.0.x` release candidate or stable
release. Older development snapshots are unsupported.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security advisory workflow for this repository and include affected versions,
reproduction steps, impact, and any proposed mitigation. Avoid including real
credentials, private keys, customer data, or live infrastructure details.

## Deployment baseline

- Release archives never contain credentials, TLS private keys, vault keys, or
  bootstrap passwords.
- Each installation must be initialized once with `TeamServer init`.
- Production requires externally provisioned TLS material with private-file
  permissions and should enable mTLS.
- The instance directory, especially `secrets/`, must be backed up through an
  encrypted mechanism and restricted to the TeamServer service account.
- Delete `secrets/bootstrap.txt` after the first administrator credential has
  been transferred to the intended secret manager.

See `TeamServer/README-FIRST-RUN.md` in the release for exact commands.
