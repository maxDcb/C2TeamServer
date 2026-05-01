from types import SimpleNamespace

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

import C2Client.TerminalPanel as terminal_panel


class FakeGrpc:
    def __init__(self):
        self.commands = []

    def sendTermCmd(self, command):
        self.commands.append(command.cmd)
        if command.cmd.startswith(terminal_panel.GrpcInfoListenerInstruction):
            return SimpleNamespace(result="http\n127.0.0.1\n8080\n/uploads/\n", data=b"")
        if command.cmd.startswith(terminal_panel.GrpcGetBeaconBinaryInstruction):
            return SimpleNamespace(result="ok", data=b"beacon")
        if command.cmd.startswith(terminal_panel.GrpcPutIntoUploadDirInstruction):
            return SimpleNamespace(result="ok", data=b"")
        return SimpleNamespace(result="Error: unexpected command", data=b"")


class FakeDropperModule:
    @staticmethod
    def getTargetOsExploration():
        return "windows"

    @staticmethod
    def generatePayloadsExploration(binary, binaryArgs, rawShellCode, url, aditionalArgs):
        return [], [], "generated"


FakeDropperModule.__name__ = "FakeDropper"


def test_extract_dropper_target_arch_accepts_aliases_and_removes_flag():
    target_arch, remaining = terminal_panel.extractDropperTargetArch(
        ["--arch", "aarch64", "--other", "value"],
        "amd64",
    )

    assert target_arch == "arm64"
    assert remaining == ["--other", "value"]


def test_dropper_arch_help_and_file_names_are_arch_specific():
    assert "Dropper Config BeaconArch x86|x64|arm64" in terminal_panel.DropperArchitectureHelp
    assert terminal_panel.makeBeaconFilePath("windows", "arm64") == "./Beacon-arm64.exe"
    assert terminal_panel.makeBeaconFilePath("linux", "x64") == "./Beacon-linux"


def test_dropper_worker_requests_selected_windows_arch(tmp_path, monkeypatch, qtbot):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(terminal_panel, "DropperModules", [FakeDropperModule])
    donut_calls = []

    def fake_create_donut_shellcode(beacon_file_path, beacon_arg, target_arch, output_path=terminal_panel.DonutShellcodeFileName):
        donut_calls.append((beacon_file_path, beacon_arg, target_arch, output_path))
        (tmp_path / output_path).write_bytes(b"shellcode")
        return ""

    monkeypatch.setattr(terminal_panel, "createDonutShellcode", fake_create_donut_shellcode)

    grpc = FakeGrpc()
    worker = terminal_panel.DropperWorker(
        grpc,
        "Dropper FakeDropper dl beacon --arch arm64",
        "fakedropper",
        "dl",
        "beacon",
        "",
        terminal_panel.ShellcodeGeneratorDonut,
        "arm64",
    )

    results = []
    worker.finished.connect(lambda command, result: results.append((command, result)))
    worker.run()

    assert "getBeaconBinary beacon windows arm64" in grpc.commands
    assert donut_calls[0][0] == "./Beacon-arm64.exe"
    assert donut_calls[0][2] == "arm64"
    assert (tmp_path / "Beacon-arm64.exe").read_bytes() == b"beacon"
    assert results == [("Dropper FakeDropper dl beacon --arch arm64", "generated")]


def test_create_donut_shellcode_reports_subprocess_crash(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    class Completed:
        returncode = -11
        stderr = ""
        stdout = ""

    monkeypatch.setattr(terminal_panel.subprocess, "run", lambda *args, **kwargs: Completed())

    error = terminal_panel.createDonutShellcode("./Beacon-arm64.exe", "127.0.0.1 443 https", "arm64")

    assert error == "Donut shellcode generation crashed with signal 11."
