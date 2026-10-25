# Exploration 0.18.0

This release includes C2TeamServer, its client and modules, and pinned 0.18.0
Windows and Linux implant assets.

## Highlights

- Install or update the server and client on Linux/WSL with the UV based
  installer. Authentication is enabled by default with Argon2id password hashes.
- Improve child listener routing and beacon stop lifecycle, including a client
  confirmation that identifies listeners hosted by the beacon being stopped.
- Make SOCKS5 routes and listener sessions more resilient under concurrent use.
- Persist V2 jobs and command outcomes so the client can recover after a
  disconnect or TeamServer restart.
- Record metadata-only operator audit events in the client and TeamServer.

The GitHub beacon transport and Linux SMB beacon are excluded from this bundle.
The release includes `Release.tar.gz`, its SHA-256 checksum, and `install.sh`.
