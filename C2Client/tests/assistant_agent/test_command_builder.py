from __future__ import annotations

import pytest

from C2Client.assistant_agent.tools.command_builder import build_command_line
from C2Client.assistant_agent.tools.command_specs import command_spec_to_tool_spec

from helpers import arg, command_spec


def tool_spec(command):
    return command_spec_to_tool_spec(command)


def test_build_command_line_quotes_paths_with_spaces():
    cat = tool_spec(command_spec("cat", "cat {path:q}", [arg("path", arg_type="path", required=True)]))
    ls = tool_spec(command_spec("ls", "ls {path:q?}", [arg("path", arg_type="path")]))

    assert build_command_line(cat, {"beacon_hash": "b", "listener_hash": "l", "path": "C:\\Users\\Public\\notes.txt"}) == "cat C:\\Users\\Public\\notes.txt"
    assert build_command_line(ls, {"beacon_hash": "b", "listener_hash": "l", "path": "C:\\Program Files"}) == "ls 'C:\\Program Files'"


def test_build_command_line_supports_raw_command_tail():
    run = tool_spec(command_spec("run", "run {command:raw}", [arg("command", required=True, variadic=True)]))

    assert build_command_line(
        run,
        {"beacon_hash": "b", "listener_hash": "l", "command": "whoami /all"},
    ) == "run whoami /all"


def test_build_command_line_omits_empty_optional_argument():
    enumerate_shares = tool_spec(command_spec("enumerateShares", "enumerateShares {host:q?}", [arg("host")]))
    ls = tool_spec(command_spec("ls", "ls {path:q?}", [arg("path", arg_type="path")]))

    assert build_command_line(
        enumerate_shares,
        {"beacon_hash": "b", "listener_hash": "l", "host": ""},
    ) == "enumerateShares"
    assert build_command_line(
        ls,
        {"beacon_hash": "b", "listener_hash": "l"},
    ) == "ls"


def test_build_command_line_supports_optional_flag_segments():
    dcom_exec = tool_spec(
        command_spec(
            "dcomExec",
            "dcomExec -h {h:q} -c {c:q} [-a {a:q}] [-n {n:flag}]",
            [
                arg("-h", required=True),
                arg("-c", required=True),
                arg("-a"),
                arg("-n"),
            ],
        )
    )

    assert build_command_line(
        dcom_exec,
        {
            "beacon_hash": "b",
            "listener_hash": "l",
            "h": "host1",
            "c": "cmd.exe",
            "a": "/c whoami",
            "n": True,
        },
    ) == "dcomExec -h host1 -c cmd.exe -a '/c whoami' -n"


def test_build_command_line_rejects_missing_required_argument():
    cat = tool_spec(command_spec("cat", "cat {path:q}", [arg("path", arg_type="path", required=True)]))

    with pytest.raises(KeyError):
        build_command_line(cat, {"beacon_hash": "b", "listener_hash": "l"})


@pytest.mark.parametrize(
    ("command", "arguments", "expected"),
    [
        (
            command_spec(
                "assemblyExec",
                "assemblyExec [--mode {mode}] [--donut-exe {donut_exe:q}] [--method {method:q}] [-- {arguments:raw}]",
                [
                    arg("--mode", values=["thread", "process"]),
                    arg("--donut-exe", artifact=True),
                    arg("--method"),
                    arg("arguments", variadic=True),
                ],
            ),
            {"mode": "process", "donut_exe": "Rubeus.exe", "arguments": "triage"},
            "assemblyExec --mode process --donut-exe Rubeus.exe -- triage",
        ),
        (
            command_spec(
                "inject",
                "inject --pid {pid} [--donut-exe {donut_exe:q}] [-- {arguments:raw}]",
                [
                    arg("--pid", arg_type="number", required=True),
                    arg("--donut-exe", artifact=True),
                    arg("arguments", variadic=True),
                ],
            ),
            {"pid": -1, "donut_exe": "BeaconHttp.exe", "arguments": "arg1 arg2"},
            "inject --pid -1 --donut-exe BeaconHttp.exe -- arg1 arg2",
        ),
        (
            command_spec(
                "registry",
                "registry {operation} -h {h:q} -k {k:q} [-n {n:q}]",
                [
                    arg("operation", values=["query", "set"], required=True),
                    arg("-h", required=True),
                    arg("-k", required=True),
                    arg("-n"),
                ],
            ),
            {"operation": "query", "h": "HKCU", "k": "Software\\C2", "n": "Smoke"},
            "registry query -h HKCU -k Software\\C2 -n Smoke",
        ),
        (
            command_spec(
                "spawnAs",
                "spawnAs [--no-profile {no_profile:flag}] {username:q} {password:q} -- {command:raw}",
                [
                    arg("--no-profile"),
                    arg("username", required=True),
                    arg("password", required=True),
                    arg("command", required=True, variadic=True),
                ],
            ),
            {"no_profile": True, "username": ".\\c2test", "password": "pw", "command": "cmd.exe /c whoami"},
            "spawnAs --no-profile .\\c2test pw -- cmd.exe /c whoami",
        ),
        (
            command_spec(
                "sshExec",
                "sshExec -h {h:q} [-P {P}] -u {u:q} -p {p:q} -- {command:raw}",
                [
                    arg("-h", required=True),
                    arg("-P", arg_type="number"),
                    arg("-u", required=True),
                    arg("-p", required=True),
                    arg("command", required=True, variadic=True),
                ],
            ),
            {"h": "server", "P": 2222, "u": "admin", "p": "pw", "command": "/bin/id"},
            "sshExec -h server -P 2222 -u admin -p pw -- /bin/id",
        ),
    ],
)
def test_build_command_lines_from_command_spec_templates(command, arguments, expected):
    arguments = {"beacon_hash": "b", "listener_hash": "l", **arguments}
    assert build_command_line(tool_spec(command), arguments) == expected
