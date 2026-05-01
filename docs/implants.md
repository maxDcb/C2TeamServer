# Implant Asset Contract

TeamServer release packaging imports assets from:

- [C2Implant](https://github.com/maxDcb/C2Implant)
- [C2LinuxImplant](https://github.com/maxDcb/C2LinuxImplant)

## Final TeamServer Layout

```text
Release/
  WindowsBeacons/
    x86/
    x64/
    arm64/
  WindowsModules/
    x86/
    x64/
    arm64/
  LinuxBeacons/
  LinuxModules/
```

## C2Implant Assets

C2Implant Windows releases are imported from one archive per architecture:

```text
C2Implant-windows-x86.zip
C2Implant-windows-x64.zip
C2Implant-windows-arm64.zip
```

Each architecture archive must contain one of these layouts:

```text
Release/WindowsBeacons/
Release/WindowsModules/
```

or:

```text
WindowsBeacons/
WindowsModules/
```

The importer stages each archive into:

```text
Release/WindowsBeacons/<arch>/
Release/WindowsModules/<arch>/
```

## Accepted C2LinuxImplant Layouts

```text
Release/LinuxBeacons/
Release/LinuxModules/
```

or:

```text
LinuxBeacons/
LinuxModules/
```

Legacy layouts are rejected:

```text
Release/Beacons/
Release/Modules/
```

## Import Latest Releases

```bash
python packaging/import_implant_releases.py \
  --stage-root build/release-staging/Release \
  --import-root build/release-imports
```

## Import Pinned Releases

```bash
python packaging/import_implant_releases.py \
  --stage-root build/release-staging/Release \
  --import-root build/release-imports \
  --windows-tag 0.15.0 \
  --linux-tag 0.14.0
```

## Validate Complete Staging

```bash
python packaging/validate_release.py \
  --release-root build/release-staging/Release \
  --require-implants
```

## Notes

- Default import uses latest GitHub releases.
- Use explicit tags for reproducible release builds.
- Import writes only into release staging.
- Source directories are not renamed, deleted, or mutated.
