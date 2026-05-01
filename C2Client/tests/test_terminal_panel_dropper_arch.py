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


def test_dropper_worker_requests_selected_windows_arch(tmp_path, monkeypatch, qtbot):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(terminal_panel, "DropperModules", [FakeDropperModule])
    donut_calls = []
    monkeypatch.setattr(terminal_panel.donut, "create", lambda **kwargs: donut_calls.append(kwargs) or b"shellcode")

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
    assert donut_calls[0]["arch"] == terminal_panel.donutArchValue("arm64")
    assert results == [("Dropper FakeDropper dl beacon --arch arm64", "generated")]
