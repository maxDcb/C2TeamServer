from __future__ import annotations

from typing import Any

from agent_core import DomainHooks


class C2DomainHooks(DomainHooks):
    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, Any]] = {}
        self.active_session_key: str | None = None
        self.recent_observations: list[dict[str, str]] = []

    def record_session_event(
        self,
        *,
        action: str,
        beacon_hash: str,
        listener_hash: str,
        hostname: str,
        username: str,
        arch: str,
        privilege: str,
        os_name: str,
        killed: Any = False,
    ) -> None:
        if not beacon_hash:
            return

        killed = self._is_truthy(killed)
        key = self._session_key(beacon_hash, listener_hash)
        if action == "stop" or killed:
            session = self.sessions.get(key, {})
            session.update({
                "beacon_hash": beacon_hash,
                "listener_hash": listener_hash,
                "hostname": hostname or session.get("hostname", ""),
                "username": username or session.get("username", ""),
                "arch": arch or session.get("arch", ""),
                "privilege": privilege or session.get("privilege", ""),
                "os": os_name or session.get("os", ""),
                "killed": True,
            })
            self.sessions[key] = session
            if self.active_session_key == key:
                self.active_session_key = None
            return

        session = self.sessions.get(key, {})
        session.update({
            "beacon_hash": beacon_hash,
            "listener_hash": listener_hash,
            "hostname": hostname or session.get("hostname", ""),
            "username": username or session.get("username", ""),
            "arch": arch or session.get("arch", ""),
            "privilege": privilege or session.get("privilege", ""),
            "os": os_name or session.get("os", ""),
            "killed": False,
        })
        self.sessions[key] = session

    def record_active_session(self, *, beacon_hash: str, listener_hash: str) -> None:
        if not beacon_hash:
            return
        key = self._session_key(beacon_hash, listener_hash)
        session = self.sessions.get(key)
        if session and session.get("killed"):
            return
        if session is None:
            self.sessions[key] = {
                "beacon_hash": beacon_hash,
                "listener_hash": listener_hash,
                "hostname": "",
                "username": "",
                "arch": "",
                "privilege": "",
                "os": "",
                "killed": False,
            }
        self.active_session_key = key

    def record_console_observation(
        self,
        *,
        beacon_hash: str,
        listener_hash: str,
        command: str,
        output: str,
    ) -> None:
        if not command and not output:
            return
        self.recent_observations.append(
            {
                "beacon_hash": beacon_hash,
                "listener_hash": listener_hash,
                "command": command[:500],
                "output_preview": output[:2000],
            }
        )
        self.recent_observations = self.recent_observations[-10:]

    def build_system_prompt_blocks(self, *, settings, session_manager) -> list[str]:
        lines = ["C2 runtime context:"]
        live_sessions = [session for session in self.sessions.values() if not session.get("killed")]
        killed_sessions = [session for session in self.sessions.values() if session.get("killed")]
        active_session = self._effective_active_session(live_sessions)
        if active_session and not active_session.get("killed"):
            lines.append(
                "Active selected session: short_beacon={short_beacon}, beacon_hash={beacon_hash}, listener_hash={listener_hash}, host={hostname}, "
                "user={username}, arch={arch}, privilege={privilege}, os={os}. Use this session for current beacon/current session requests.".format(
                    **self._format_session(active_session)
                )
            )
        else:
            lines.append(
                "Active selected session: none. If exactly one live session is listed, use it for current beacon/current session requests; otherwise ask the operator to select a live session."
            )

        if live_sessions:
            lines.append("Known live sessions. Match short operator references like `mz` against beacon_hash prefixes:")
            for session in live_sessions:
                lines.append(
                    "- short_beacon={short_beacon}, beacon_hash={beacon_hash}, listener_hash={listener_hash}, host={hostname}, "
                    "user={username}, arch={arch}, privilege={privilege}, os={os}".format(**self._format_session(session))
                )
        else:
            lines.append("Known live sessions: none.")

        if killed_sessions:
            lines.append("Killed sessions are invalid targets:")
            for session in killed_sessions[-5:]:
                lines.append(
                    "- short_beacon={short_beacon}, beacon_hash={beacon_hash}, listener_hash={listener_hash}, host={hostname}, user={username}".format(
                        **self._format_session(session)
                    )
                )

        if self.recent_observations:
            lines.append("Recent console observations:")
            for observation in self.recent_observations:
                lines.append(
                    "- beacon_hash={beacon_hash}, listener_hash={listener_hash}, command={command}, output_preview={output_preview}".format(
                        **observation
                    )
                )
        return ["\n".join(lines)]

    def _effective_active_session(self, live_sessions: list[dict[str, Any]]) -> dict[str, Any] | None:
        active_session = self.sessions.get(self.active_session_key or "")
        if active_session and not active_session.get("killed"):
            return active_session

        live_by_key = {
            self._session_key(session.get("beacon_hash", ""), session.get("listener_hash", "")): session
            for session in live_sessions
        }
        for observation in reversed(self.recent_observations):
            key = self._session_key(observation.get("beacon_hash", ""), observation.get("listener_hash", ""))
            session = live_by_key.get(key)
            if session is not None:
                return session

        if len(live_sessions) == 1:
            return live_sessions[0]
        return None

    def _format_session(self, session: dict[str, Any]) -> dict[str, Any]:
        formatted = dict(session)
        formatted["short_beacon"] = str(formatted.get("beacon_hash", ""))[:8]
        return formatted

    def _session_key(self, beacon_hash: str, listener_hash: str) -> str:
        return f"{beacon_hash}:{listener_hash}"

    def _is_truthy(self, value: Any) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "killed", "dead", "stop", "stopped"}
        return bool(value)
