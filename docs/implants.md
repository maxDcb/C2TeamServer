# Implant Asset Contract

TeamServer release packaging imports assets from:

- [C2Implant](https://github.com/maxDcb/C2Implant)
- [C2LinuxImplant](https://github.com/maxDcb/C2LinuxImplant)

## Final TeamServer Layout

```text
Release/
  WindowsBeacons/
  WindowsModules/
  LinuxBeacons/
  LinuxModules/
```

## Accepted C2Implant Layouts

```text
Release/WindowsBeacons/
Release/WindowsModules/
```

or:

```text
WindowsBeacons/
WindowsModules/
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
  --windows-tag 0.14.0 \
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
