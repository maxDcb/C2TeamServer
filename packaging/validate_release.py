from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


EXPECTED_TEAMSERVER_FILES = (
    "TeamServer",
    "TeamServerConfig.json",
    "auth_credentials.json",
    "localhost.crt",
    "localhost.key",
    "rootCA.crt",
    "server.crt",
    "server.key",
)

EXPECTED_TEAMSERVER_MODULES = (
    "libAssemblyExec.so",
    "libCat.so",
    "libChangeDirectory.so",
    "libChisel.so",
    "libCimExec.so",
    "libCoff.so",
    "libDcomExec.so",
    "libDotnetExec.so",
    "libDownload.so",
    "libEnumerateRdpSessions.so",
    "libEnumerateShares.so",
    "libEvasion.so",
    "libGetEnv.so",
    "libInject.so",
    "libIpConfig.so",
    "libKerberosUseTicket.so",
    "libKeyLogger.so",
    "libKillProcess.so",
    "libListDirectory.so",
    "libListProcesses.so",
    "libMakeToken.so",
    "libMiniDump.so",
    "libMkDir.so",
    "libNetstat.so",
    "libPowershell.so",
    "libPrintWorkingDirectory.so",
    "libPsExec.so",
    "libPwSh.so",
    "libRegistry.so",
    "libRemove.so",
    "libRev2self.so",
    "libRun.so",
    "libScreenShot.so",
    "libScript.so",
    "libShell.so",
    "libSpawnAs.so",
    "libSshExec.so",
    "libStealToken.so",
    "libTaskScheduler.so",
    "libTree.so",
    "libUpload.so",
    "libWhoami.so",
    "libWinRM.so",
    "libWmiExec.so",
    "libReversePortForward.so",
)

EXPECTED_WINDOWS_ARCHES = (
    "x86",
    "x64",
    "arm64",
)

EXPECTED_LINUX_ARCHES = (
    "x64",
)

EXPECTED_WINDOWS_BEACONS = (
    "BeaconDns.exe",
    "BeaconDnsDll.dll",
    "BeaconGithub.exe",
    "BeaconGithubDll.dll",
    "BeaconHttp.exe",
    "BeaconHttpDll.dll",
    "BeaconSmb.exe",
    "BeaconSmbDll.dll",
    "BeaconTcp.exe",
    "BeaconTcpDll.dll",
)

EXPECTED_WINDOWS_MODULES = (
    "AssemblyExec.dll",
    "Cat.dll",
    "ChangeDirectory.dll",
    "Chisel.dll",
    "CimExec.dll",
    "Coff.dll",
    "DcomExec.dll",
    "DotnetExec.dll",
    "Download.dll",
    "EnumerateRdpSessions.dll",
    "EnumerateShares.dll",
    "Evasion.dll",
    "GetEnv.dll",
    "Inject.dll",
    "IpConfig.dll",
    "KerberosUseTicket.dll",
    "KeyLogger.dll",
    "KillProcess.dll",
    "ListDirectory.dll",
    "ListProcesses.dll",
    "MakeToken.dll",
    "MiniDump.dll",
    "MkDir.dll",
    "Netstat.dll",
    "Powershell.dll",
    "PrintWorkingDirectory.dll",
    "PsExec.dll",
    "PwSh.dll",
    "Registry.dll",
    "Remove.dll",
    "Rev2self.dll",
    "Run.dll",
    "ScreenShot.dll",
    "Script.dll",
    "Shell.dll",
    "SpawnAs.dll",
    "SshExec.dll",
    "StealToken.dll",
    "TaskScheduler.dll",
    "Tree.dll",
    "Upload.dll",
    "Whoami.dll",
    "WinRM.dll",
    "WmiExec.dll",
    "ReversePortForward.dll",
)

EXPECTED_LINUX_BEACONS = (
    "BeaconDns",
    "BeaconGithub",
    "BeaconHttp",
    "BeaconSmb",
    "BeaconTcp",
)

EXPECTED_LINUX_MODULES = EXPECTED_TEAMSERVER_MODULES

EXPECTED_COMMAND_SPECS_COMMON = (
    "sleep.json",
    "end.json",
    "help.json",
    "listener.json",
    "listModule.json",
    "loadModule.json",
    "unloadModule.json",
)

EXPECTED_COMMAND_SPECS_MODULES = (
    "assemblyExec.json",
    "cat.json",
    "cd.json",
    "chisel.json",
    "cimExec.json",
    "dcomExec.json",
    "download.json",
    "enumerateRdpSessions.json",
    "enumerateShares.json",
    "evasion.json",
    "getEnv.json",
    "inject.json",
    "ipConfig.json",
    "kerberosUseTicket.json",
    "keyLogger.json",
    "killProcess.json",
    "ls.json",
    "makeToken.json",
    "miniDump.json",
    "mkDir.json",
    "netstat.json",
    "ps.json",
    "psExec.json",
    "powershell.json",
    "pwd.json",
    "registry.json",
    "remove.json",
    "rev2self.json",
    "reversePortForward.json",
    "run.json",
    "screenShot.json",
    "shell.json",
    "script.json",
    "spawnAs.json",
    "sshExec.json",
    "stealToken.json",
    "taskScheduler.json",
    "tree.json",
    "upload.json",
    "whoami.json",
    "winRm.json",
    "wmiExec.json",
)


class ValidationError(RuntimeError):
    pass


def _relative_files(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }


def _require_non_empty_file(path: Path) -> None:
    if not path.is_file():
        raise ValidationError(f"Missing required file: {path}")
    if path.stat().st_size == 0:
        raise ValidationError(f"Required file is empty: {path}")


def _require_executable(path: Path) -> None:
    _require_non_empty_file(path)
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise ValidationError(f"Required file is not executable: {path}")


def _require_directory_exact(root: Path, expected_files: tuple[str, ...]) -> None:
    if not root.is_dir():
        raise ValidationError(f"Missing required directory: {root}")

    expected = set(expected_files)
    actual = _relative_files(root)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)

    if missing:
        raise ValidationError(f"{root} is missing expected file(s): {', '.join(missing)}")
    if unexpected:
        raise ValidationError(f"{root} contains unexpected file(s): {', '.join(unexpected)}")

    for relative in expected_files:
        _require_non_empty_file(root / relative)


def _require_arch_directories_exact(
    root: Path,
    expected_arches: tuple[str, ...],
    expected_files: tuple[str, ...],
) -> None:
    if not root.is_dir():
        raise ValidationError(f"Missing required directory: {root}")

    expected = set(expected_arches)
    actual_dirs = {path.name for path in root.iterdir() if path.is_dir()}
    actual_files = {path.name for path in root.iterdir() if path.is_file()}

    missing = sorted(expected - actual_dirs)
    unexpected_dirs = sorted(actual_dirs - expected)
    unexpected_files = sorted(actual_files)

    if missing:
        raise ValidationError(f"{root} is missing expected arch directories: {', '.join(missing)}")
    if unexpected_dirs:
        raise ValidationError(f"{root} contains unexpected arch directories: {', '.join(unexpected_dirs)}")
    if unexpected_files:
        raise ValidationError(f"{root} contains unexpected file(s): {', '.join(unexpected_files)}")

    for arch in expected_arches:
        _require_directory_exact(root / arch, expected_files)


def validate_base_release(release_root: Path) -> None:
    if not release_root.is_dir():
        raise ValidationError(f"Release root does not exist: {release_root}")

    teamserver_root = release_root / "TeamServer"
    modules_root = release_root / "TeamServerModules"
    command_specs_root = release_root / "CommandSpecs"
    client_root = release_root / "Client"

    if not teamserver_root.is_dir():
        raise ValidationError(f"Missing TeamServer directory: {teamserver_root}")
    for filename in EXPECTED_TEAMSERVER_FILES:
        path = teamserver_root / filename
        if filename == "TeamServer":
            _require_executable(path)
        else:
            _require_non_empty_file(path)

    if not (teamserver_root / "logs").is_dir():
        raise ValidationError(f"Missing TeamServer logs directory: {teamserver_root / 'logs'}")

    runtime_data_roots = ("data", "Tools", "Scripts", "UploadedArtifacts", "GeneratedArtifacts", "www")
    packaged_data_roots = [name for name in runtime_data_roots if (release_root / name).exists()]
    if packaged_data_roots:
        raise ValidationError(
            "Release staging contains runtime/operator data directories: "
            + ", ".join(packaged_data_roots)
        )

    _require_directory_exact(modules_root, EXPECTED_TEAMSERVER_MODULES)

    for spec in EXPECTED_COMMAND_SPECS_COMMON:
        _require_non_empty_file(command_specs_root / "common" / spec)
    for spec in EXPECTED_COMMAND_SPECS_MODULES:
        _require_non_empty_file(command_specs_root / "modules" / spec)

    _require_non_empty_file(client_root / "README.md")
    _require_non_empty_file(client_root / "pyproject.toml")
    _require_non_empty_file(client_root / "requirements.txt")
    _require_executable(client_root / "run-client.sh")
    _require_non_empty_file(client_root / "run-client.ps1")
    if not (client_root / "c2client_protocol" / "__init__.py").is_file():
        raise ValidationError(
            f"Missing required file: {client_root / 'c2client_protocol' / '__init__.py'}"
        )
    _require_non_empty_file(client_root / "c2client_protocol" / "TeamServerApi_pb2.py")
    _require_non_empty_file(client_root / "c2client_protocol" / "TeamServerApi_pb2_grpc.py")

    generated_noise = [
        path for path in release_root.rglob("*") if path.name in {".gitignore", "__pycache__"}
    ]
    if generated_noise:
        raise ValidationError(
            "Release staging contains generated/source-control noise: "
            + ", ".join(str(path) for path in generated_noise)
        )


def validate_implants(release_root: Path) -> None:
    _require_arch_directories_exact(
        release_root / "WindowsBeacons",
        EXPECTED_WINDOWS_ARCHES,
        EXPECTED_WINDOWS_BEACONS,
    )
    _require_arch_directories_exact(
        release_root / "WindowsModules",
        EXPECTED_WINDOWS_ARCHES,
        EXPECTED_WINDOWS_MODULES,
    )
    _require_arch_directories_exact(
        release_root / "LinuxBeacons",
        EXPECTED_LINUX_ARCHES,
        EXPECTED_LINUX_BEACONS,
    )
    _require_arch_directories_exact(
        release_root / "LinuxModules",
        EXPECTED_LINUX_ARCHES,
        EXPECTED_LINUX_MODULES,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a staged C2TeamServer release.")
    parser.add_argument("--release-root", required=True, help="Path to the staged Release directory.")
    parser.add_argument(
        "--require-implants",
        action="store_true",
        help="Require and validate imported C2Implant/C2LinuxImplant assets.",
    )
    args = parser.parse_args()

    release_root = Path(args.release_root).resolve()
    try:
        validate_base_release(release_root)
        if args.require_implants:
            validate_implants(release_root)
    except ValidationError as exc:
        print(f"Release validation failed: {exc}", file=sys.stderr)
        return 1

    print(f"Validated release staging: {release_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
