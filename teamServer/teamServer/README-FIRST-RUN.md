# TeamServer first run

The release contains no credentials or private keys.

For a local standalone instance, run `./TeamServer`. It creates an `instance/`
directory with a unique TLS identity, encrypted credential hashes, a public client
profile, and a private bootstrap file. Import `instance/client/client-profile.json`
with `C2Client --profile` and read the initial password from
`instance/secrets/bootstrap.txt`.

For production, provision an external certificate and key:

```bash
C2_BOOTSTRAP_PASSWORD_FILE=/run/secrets/bootstrap-password ./TeamServer init \
  --profile production \
  --instance-dir /var/lib/teamserver \
  --hostname teamserver.example.internal \
  --listen-address 0.0.0.0 \
  --tls-cert /run/secrets/server.crt \
  --tls-key /run/secrets/server.key \
  --trust-cert /run/secrets/operator-trust.crt \
  --client-ca /run/secrets/operator-ca.crt \
  --require-client-cert
```

Production startup is fail-closed. Private files must be accessible only by the
TeamServer account. The development profile can only bind to loopback.

