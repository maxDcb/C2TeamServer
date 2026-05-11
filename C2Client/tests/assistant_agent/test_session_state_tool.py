from __future__ import annotations

from types import SimpleNamespace

from C2Client.assistant_agent.tools.session_state_tool import C2LiveSessionsTool, list_sessions


class StubGrpc:
    def __init__(self):
        self.sessions = [
            SimpleNamespace(
                beacon_hash="mzBlbIj35qewE7Rpa51oRltFoaNahMJB",
                listener_hash="listener-live",
                hostname="desktop",
                username="max",
                arch="x64",
                os="windows",
                killed=False,
            ),
            SimpleNamespace(
                beacon_hash="deadbeef",
                listener_hash="listener-dead",
                hostname="old",
                username="max",
                arch="x64",
                os="windows",
                killed=True,
            ),
        ]

    def listSessions(self):
        return iter(self.sessions)


def test_live_sessions_tool_formats_live_sessions_and_short_hashes():
    tool = C2LiveSessionsTool(StubGrpc())

    result = tool.execute({"beacon_prefix": "mz"}, context=None)

    assert result.ok is True
    assert "mzBlbIj3" in result.content
    assert "mzBlbIj35qewE7Rpa51oRltFoaNahMJB" in result.content
    assert "listener-live" in result.content
    assert "deadbeef" not in result.content


def test_list_sessions_can_include_killed_sessions():
    sessions = list_sessions(StubGrpc(), include_killed=True)

    assert [session.beacon_hash for session in sessions] == [
        "mzBlbIj35qewE7Rpa51oRltFoaNahMJB",
        "deadbeef",
    ]
