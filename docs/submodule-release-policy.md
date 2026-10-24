# Submodule release policy

The shared C2 submodules use one linear `master` branch per repository. A parent
repository pins an exact commit; it does not follow the branch automatically.

## Shared version gate

Before publishing a new shared submodule commit:

1. Put the candidate commit on local `master` in the submodule repository.
   Fast-forward from the published `master`; do not rewrite its history.
2. Pin that exact commit in C2TeamServer, C2Implant, and C2LinuxImplant.
3. Run `python3 scripts/check-submodule-alignment.py <teamserver> <windows-implant> <linux-implant>`
   from this repository. It must report `OK` for every shared gitlink.
4. Build and run the complete CTest suite for TeamServer and the Linux implant
   on Linux/WSL, and for the Windows implant with MSVC on Windows. Resolve every
   failure and repeat the affected validation. Run client tests when the client
   or a contract it consumes changes.
5. Push the validated submodule `master` commits first. Push the three parent
   commits only after their gitlinks are reachable from those remote branches.

Do not advance a submodule `master` on the strength of a single consumer's test
suite. Keep the parent gitlinks pinned so builds remain reproducible.

`MemoryModule` and `COFFLoader` currently have only one consumer, the Windows
implant. Promote their validated development commits to local `master` and use
the same build/test rule for that consumer before publishing. `COFFLoader` has
no remote `master` yet; create it and update its default branch when publishing.
Third-party submodules remain pinned to reviewed upstream commits.

This is a release procedure and a version check, not an automatic server-side
push restriction. Publishing to `master` still requires the maintainer to run
the gate and inspect its results.
