# Changelog

## 1.0.0-rc.1

- Introduces per-installation instance provisioning with no distributed secrets.
- Requires authenticated TLS for every gRPC connection; production supports
  external PKI and mandatory client certificates.
- Replaces legacy password and token handling with PBKDF2-SHA256, secure random
  tokens, expiry, lockout, and viewer/operator/admin authorization.
- Adds a versioned client connection profile and removes the bundled client CA.
- Keeps credential-vault data encrypted with AES-256-GCM and records the acting
  principal in vault audit events.
- Adds release secret scanning, runtime bootstrap integration coverage, hardened
  linker flags, pinned release inputs, and a non-root container runtime.

This candidate intentionally drops the legacy flat configuration and packaged
credential/certificate contracts.
