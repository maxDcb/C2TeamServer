# Linux and WSL installation

## Install

The default command installs both the TeamServer and the Python GUI client:

```bash
curl -fsSL https://github.com/maxDcb/C2TeamServer/releases/latest/download/install.sh | bash
```

Use `--server-only` or `--client-only` to install one component. A client-only install
needs the TeamServer's public trust certificate:

```bash
curl -fsSL https://github.com/maxDcb/C2TeamServer/releases/latest/download/install.sh |
  bash -s -- --client-only --hostname teamserver.example.org --ca-cert ./trust.crt
```

The bootstrap downloads the selected release archive and its SHA-256 checksum. It checks
the checksum before extracting the archive and rejects links or paths outside `Release/`.
Use `--version TAG` to install a specific release, `--bundle FILE` for a local
`Release.tar.gz`, or `--bundle DIRECTORY` for a staged `Release/` directory. A local
bundle is trusted as supplied by the operator.

```bash
bash install.sh --bundle build/release-staging/Release --server-only
```

The default prefix is `~/.local/Exploration`; use `--prefix /absolute/path` to change it.
Installation runs as the current user without `sudo`. The installer adds an
`exploration` link to `~/.local/bin` when that name is free. If the directory is not in
`PATH`, use `~/.local/Exploration/bin/exploration` directly.

The TeamServer requires the system `libargon2` and SQLite runtimes. OpenSSL is required
when generating a certificate. The GUI requires the Qt system libraries listed in
[build dependencies](build.md). uv is used only when installing the client: the installer
uses an existing `uv` executable or installs a pinned version inside the prefix. It
creates Python 3.12 and synchronizes the client from the shipped `uv.lock`.
On Ubuntu or WSL, the server prerequisites can be installed with
`sudo apt-get install libargon2-1 libsqlite3-0 openssl`.

## First run and credentials

The installer creates `server/config/TeamServerConfig.json` with absolute paths inside the
chosen prefix. The application files are under `server/app/Release`, while the SQLite
database, artifacts, logs, certificates and account file live outside that directory.
The server launcher sets the working directory needed by existing relative log paths.
Bundled build certificates and development credentials are removed from the installed
application before first run.

Without `--tls-cert` and `--tls-key`, the installer creates a unique self-signed server
certificate for `localhost`, `127.0.0.1` and the optional `--hostname`. For a remote
TeamServer, provide its reachable name with `--hostname`. To use an existing certificate,
pass both `--tls-cert` and `--tls-key`, plus `--ca-cert` if clients must trust a separate
CA. Private keys are copied with owner-only permissions. A combined installation copies
only the public trust certificate into `client/config`.

The installer generates an admin password, stores only its Argon2id hash and prints the
password once after installation. You can supply `--admin-password-file PATH` instead
for automation; the file is read locally and its contents are not printed. Save the
initial password in a password manager. The client prompts for it on launch.
Authentication is mandatory: the TeamServer refuses to start if its account file is
missing or invalid. Existing SHA-256 account hashes are upgraded to Argon2id after a
successful login when the account file is writable.
If the initial password is lost, `exploration server reset-admin` generates a new one
and restarts the server if it is running.

## Commands and updates

```bash
exploration server run             # foreground
exploration server start           # background
exploration server status
exploration server logs
exploration server logs --follow
exploration server stop
exploration server reset-admin
exploration client
exploration client start
exploration client status
exploration client stop
exploration update                 # latest release
exploration update --version TAG
exploration update --bundle ./Release.tar.gz
```

The server is not started automatically by installation. `server start` records its PID
under `server/data`; `server stop` checks that the PID still belongs to this installation.
The client stores its connection settings in `client/config/client.env` and its local
history and logs under `client/data`.

An update replaces the selected application files and synchronizes the client's Python
environment. It preserves `server/config`, `server/data`, `server/logs`,
`client/config` and `client/data`. If the server was running, the update stops it and
starts it again. Back up the SQLite database together with its WAL files while the server
is stopped before a major version change.
