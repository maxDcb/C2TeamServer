from __future__ import annotations

from C2Client.assistant_agent.domain.hooks import C2DomainHooks


def test_domain_hooks_render_sessions_and_recent_observations():
    hooks = C2DomainHooks()
    hooks.record_session_event(
        action="start",
        beacon_hash="beacon",
        listener_hash="listener",
        hostname="host",
        username="user",
        arch="x64",
        privilege="high",
        os_name="windows",
    )
    for index in range(12):
        hooks.record_console_observation(
            beacon_hash="beacon",
            listener_hash="listener",
            command=f"cmd-{index}",
            output=f"output-{index}",
        )

    rendered = hooks.build_system_prompt_blocks(settings=None, session_manager=None)[0]

    assert "beacon_hash=beacon" in rendered
    assert "cmd-2" in rendered
    assert "command=cmd-1," not in rendered
