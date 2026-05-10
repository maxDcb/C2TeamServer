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
    hooks.record_active_session(beacon_hash="beacon", listener_hash="listener")
    for index in range(12):
        hooks.record_console_observation(
            beacon_hash="beacon",
            listener_hash="listener",
            command=f"cmd-{index}",
            output=f"output-{index}",
        )

    rendered = hooks.build_system_prompt_blocks(settings=None, session_manager=None)[0]

    assert "Active selected session: short_beacon=beacon, beacon_hash=beacon" in rendered
    assert "beacon_hash=beacon" in rendered
    assert "cmd-2" in rendered
    assert "command=cmd-1," not in rendered


def test_domain_hooks_do_not_keep_killed_session_active():
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
    hooks.record_active_session(beacon_hash="beacon", listener_hash="listener")

    hooks.record_session_event(
        action="update",
        beacon_hash="beacon",
        listener_hash="listener",
        hostname="host",
        username="user",
        arch="x64",
        privilege="high",
        os_name="windows",
        killed=True,
    )

    rendered = hooks.build_system_prompt_blocks(settings=None, session_manager=None)[0]

    assert "Active selected session: none" in rendered
    assert "Killed sessions are invalid targets" in rendered


def test_domain_hooks_use_only_live_session_as_effective_active_session():
    hooks = C2DomainHooks()
    hooks.record_session_event(
        action="start",
        beacon_hash="mzBlbIj35qewE7Rpa51oRltFoaNahMJB",
        listener_hash="listener",
        hostname="host",
        username="user",
        arch="x64",
        privilege="medium",
        os_name="windows",
    )

    rendered = hooks.build_system_prompt_blocks(settings=None, session_manager=None)[0]

    assert "Active selected session: short_beacon=mzBlbIj3" in rendered
    assert "Use this session for current beacon/current session requests" in rendered
    assert "Match short operator references like `mz`" in rendered


def test_domain_hooks_use_recent_live_console_observation_as_effective_active_session():
    hooks = C2DomainHooks()
    hooks.record_session_event(
        action="start",
        beacon_hash="old",
        listener_hash="listener-old",
        hostname="old-host",
        username="user",
        arch="x64",
        privilege="medium",
        os_name="windows",
    )
    hooks.record_session_event(
        action="start",
        beacon_hash="new",
        listener_hash="listener-new",
        hostname="new-host",
        username="user",
        arch="x64",
        privilege="medium",
        os_name="windows",
    )
    hooks.record_console_observation(
        beacon_hash="new",
        listener_hash="listener-new",
        command="ls",
        output="ok",
    )

    rendered = hooks.build_system_prompt_blocks(settings=None, session_manager=None)[0]

    assert "Active selected session: short_beacon=new, beacon_hash=new" in rendered
