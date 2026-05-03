from __future__ import annotations

from typing import Any

from agent_core import DomainHooks


class C2DomainHooks(DomainHooks):
    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, Any]] = {}
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
    ) -> None:
        if action == "start":
            self.sessions[beacon_hash] = {
                "beacon_hash": beacon_hash,
                "listener_hash": listener_hash,
                "hostname": hostname,
                "username": username,
                "arch": arch,
                "privilege": privilege,
                "os": os_name,
            }
        elif action == "stop":
            self.sessions.pop(beacon_hash, None)

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
        if self.sessions:
            lines.append("Known sessions:")
            for session in self.sessions.values():
                lines.append(
                    "- beacon_hash={beacon_hash}, listener_hash={listener_hash}, host={hostname}, "
                    "user={username}, arch={arch}, privilege={privilege}, os={os}".format(**session)
                )
        else:
            lines.append("Known sessions: none. Ask the operator to select or provide a session before using C2 tools.")

        if self.recent_observations:
            lines.append("Recent console observations:")
            for observation in self.recent_observations:
                lines.append(
                    "- beacon_hash={beacon_hash}, listener_hash={listener_hash}, command={command}, output_preview={output_preview}".format(
                        **observation
                    )
                )
        return ["\n".join(lines)]
