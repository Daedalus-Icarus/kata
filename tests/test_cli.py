from __future__ import annotations

from kata.cli import build_parser


def test_top_level_cli_exposes_agent_competition_commands() -> None:
    parser = build_parser()
    subparser_action = next(
        action
        for action in parser._actions
        if getattr(action, "choices", None)
    )
    commands = set(subparser_action.choices)

    assert {"frontier", "challenge", "submission", "eval-pack", "registry", "report"} <= commands
    assert "generate" not in commands
    assert "baseline" not in commands
    assert "eval" not in commands
