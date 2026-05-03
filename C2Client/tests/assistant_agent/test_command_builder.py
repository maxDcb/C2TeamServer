from __future__ import annotations

import pytest

from C2Client.assistant_agent.tools.command_builder import build_command_line
from C2Client.assistant_agent.tools.loader import C2ToolSpec, load_tool_specs


def spec_by_name(name: str) -> C2ToolSpec:
    return {spec.name: spec for spec in load_tool_specs()}[name]


def test_build_command_line_quotes_paths_with_spaces():
    assert build_command_line(spec_by_name("cat"), {"beacon_hash": "b", "listener_hash": "l", "path": "C:\\Users\\Public\\notes.txt"}) == "cat C:\\Users\\Public\\notes.txt"
    assert build_command_line(spec_by_name("ls"), {"beacon_hash": "b", "listener_hash": "l", "path": "C:\\Program Files"}) == 'ls "C:\\Program Files"'


def test_build_command_line_supports_raw_command_tail():
    assert build_command_line(
        spec_by_name("run"),
        {"beacon_hash": "b", "listener_hash": "l", "command": "whoami /all"},
    ) == "run whoami /all"


def test_build_command_line_omits_empty_optional_argument():
    assert build_command_line(
        spec_by_name("enumerateShares"),
        {"beacon_hash": "b", "listener_hash": "l", "host": ""},
    ) == "enumerateShares"
    assert build_command_line(
        spec_by_name("ls"),
        {"beacon_hash": "b", "listener_hash": "l"},
    ) == "ls"


def test_build_command_line_supports_optional_flag_segments():
    assert build_command_line(
        spec_by_name("dcomExec"),
        {
            "beacon_hash": "b",
            "listener_hash": "l",
            "hostname": "host1",
            "command": "cmd.exe",
            "arguments": "/c whoami",
            "no_password": True,
        },
    ) == 'dcomExec -h host1 -c cmd.exe -a "/c whoami" -n'
    assert build_command_line(
        spec_by_name("screenShot"),
        {"beacon_hash": "b", "listener_hash": "l"},
    ) == "screenShot"


def test_build_command_line_rejects_missing_required_argument():
    with pytest.raises(KeyError):
        build_command_line(spec_by_name("cat"), {"beacon_hash": "b", "listener_hash": "l"})


@pytest.mark.parametrize(
    ("name", "arguments", "expected"),
    [
        ("assemblyExec", {"action": "thread"}, "assemblyExec thread"),
        ("cat", {"path": "C:\\Temp\\a.txt"}, "cat C:\\Temp\\a.txt"),
        ("cd", {"path": "C:\\Users\\Public"}, "cd C:\\Users\\Public"),
        ("chisel", {"binary_path_or_action": "stop", "pid": 1234}, "chisel stop 1234"),
        ("cimExec", {"hostname": "host1", "command": "cmd.exe", "arguments": "/c whoami"}, 'cimExec -h host1 -c cmd.exe -a "/c whoami"'),
        ("coffLoader", {"coff_file": "whoami.x64.o", "function_name": "go", "packed_arguments": "Zs c:\\ 0"}, "coffLoader whoami.x64.o go Zs c:\\ 0"),
        ("dcomExec", {"hostname": "host1", "command": "cmd.exe", "working_dir": "C:\\Windows"}, "dcomExec -h host1 -c cmd.exe -w C:\\Windows"),
        ("dotnetExec", {"action": "runDll", "module_name": "lib", "method_name": "Run", "arguments": "arg1 arg2"}, "dotnetExec runDll lib Run arg1 arg2"),
        ("download", {"remote_path": "C:\\Temp\\a.txt", "local_path": "/tmp/a.txt"}, "download C:\\Temp\\a.txt /tmp/a.txt"),
        ("enumerateRdpSessions", {"server": "fileserver"}, "enumerateRdpSessions -s fileserver"),
        ("enumerateShares", {"host": "fileserver"}, "enumerateShares fileserver"),
        ("evasion", {"action": "ReadMemory", "address": "0x1234", "value": "16"}, "evasion ReadMemory 0x1234 16"),
        ("getEnv", {}, "getEnv"),
        ("inject", {"payload_type": "-d", "input_file": "payload.dll", "pid": 4242, "method": "Run", "arguments": "a b"}, "inject -d payload.dll 4242 Run a b"),
        ("ipConfig", {}, "ipConfig"),
        ("kerberosUseTicket", {"ticket_file": "/tmp/ticket.kirbi"}, "kerberosUseTicket /tmp/ticket.kirbi"),
        ("keyLogger", {"action": "start"}, "keyLogger start"),
        ("killProcess", {"pid": 4242}, "killProcess 4242"),
        ("listProcesses", {}, "ps"),
        ("loadModule", {"module_to_load": "whoami.dll"}, "loadModule whoami.dll"),
        ("ls", {}, "ls"),
        ("makeToken", {"username": "DOMAIN\\user", "password": "Password123!"}, "makeToken DOMAIN\\user Password123!"),
        ("miniDump", {"action": "dump", "path": "lsass.xored"}, "miniDump dump lsass.xored"),
        ("mkDir", {"path": "C:\\Temp\\new dir"}, 'mkDir "C:\\Temp\\new dir"'),
        ("netstat", {}, "netstat"),
        ("powershell", {"command": "whoami | write-output"}, "powershell whoami | write-output"),
        ("psExec", {"auth_mode": "-u", "username": "DOMAIN\\user", "password": "pw", "target": "host1", "service_file": "svc.exe"}, "psExec -u DOMAIN\\user pw host1 svc.exe"),
        ("pwSh", {"action": "run", "command": "Get-Process"}, "pwSh run Get-Process"),
        ("pwd", {}, "pwd"),
        ("registry", {"operation": "set", "root_key": "HKLM", "sub_key": "Software\\Acme", "value_name": "Path", "value_data": "C:/Temp", "value_type": "REG_SZ"}, "registry set -h HKLM -k Software\\Acme -n Path -d C:/Temp -t REG_SZ"),
        ("remove", {"path": "C:\\Temp\\old.txt"}, "remove C:\\Temp\\old.txt"),
        ("rev2self", {}, "rev2self"),
        ("reversePortForward", {"remote_port": 8080, "local_host": "127.0.0.1", "local_port": 80}, "reversePortForward 8080 127.0.0.1 80"),
        ("run", {"command": "whoami /all"}, "run whoami /all"),
        ("screenShot", {}, "screenShot"),
        ("script", {"script_path": "/tmp/test.sh"}, "script /tmp/test.sh"),
        ("shell", {"command": "ls -la"}, "shell ls -la"),
        ("spawnAs", {"domain": "DOMAIN", "username": "user", "password": "pw", "net_only": True, "command": "cmd.exe /c whoami"}, "spawnAs -d DOMAIN --netonly user pw -- cmd.exe /c whoami"),
        ("sshExec", {"host": "host1", "username": "user", "password": "pw", "command": "id"}, "sshExec -h host1 -u user -p pw -- id"),
        ("stealToken", {"pid": 4242}, "stealToken 4242"),
        ("taskScheduler", {"command": "cmd.exe", "arguments": "/c whoami", "skip_run": True, "keep_task": True}, 'taskScheduler -c cmd.exe -a "/c whoami" --no-run --nocleanup'),
        ("tree", {}, "tree"),
        ("upload", {"local_path": "/tmp/a.txt", "remote_path": "C:\\Temp\\a.txt"}, "upload /tmp/a.txt C:\\Temp\\a.txt"),
        ("whoami", {}, "whoami"),
        ("winRm", {"auth_mode": "-n", "target": "host1", "command": "whoami"}, "winRm -n host1 whoami"),
        ("wmiExec", {"auth_mode": "-k", "dc": "dc1", "target": "host1", "command": "whoami"}, "wmiExec -k dc1 host1 whoami"),
    ],
)
def test_build_command_lines_cover_core_module_init_forms(name, arguments, expected):
    arguments = {"beacon_hash": "b", "listener_hash": "l", **arguments}
    assert build_command_line(spec_by_name(name), arguments) == expected
