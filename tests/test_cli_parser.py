"""Parser, help text and options of the CLI stay unchanged (AR-128).

Runs against the target parser."""

import argparse

import pytest

import mcpthreat_scan.cli.main as target

@pytest.fixture
def parser():
    return target.build_parser()


def _subparsers(parser):
    action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    return action.choices


def test_subcommands_are_scan_diff_and_tui_and_required(parser, capsys):
    assert set(_subparsers(parser)) == {"scan", "diff", "tui"}
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args([])
    assert excinfo.value.code == 2
    assert "usage: cli.main" in capsys.readouterr().err


def test_scan_defaults_and_options(parser):
    args = parser.parse_args(["scan", "p"])

    assert (args.path, args.format, args.ai_review, args.fail_on) == ("p", "text", False, None)
    args = parser.parse_args(["scan", "p", "--format", "sarif", "--ai-review", "--fail-on", "WARNING"])
    assert (args.format, args.ai_review, args.fail_on) == ("sarif", True, "WARNING")


def test_diff_defaults_and_options(parser):
    args = parser.parse_args(["diff", "a", "b"])

    assert (args.before, args.after, args.format) == ("a", "b", "text")
    assert parser.parse_args(["diff", "a", "b", "--format", "json"]).format == "json"


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "p", "--format", "xml"],
        ["scan", "p", "--fail-on", "FATAL"],
        ["scan"],
        ["diff", "a"],
        ["diff", "a", "b", "--fail-on", "ERROR"],
        ["bogus"],
    ],
)
def test_invalid_usage_exits_with_two(parser, argv):
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(argv)

    assert excinfo.value.code == 2


def test_choices_are_the_documented_vocabularies(parser):
    scan_actions = {a.dest: a for a in _subparsers(parser)["scan"]._actions}

    assert list(scan_actions["format"].choices) == ["text", "json", "sarif"]
    assert list(scan_actions["fail_on"].choices) == ["ERROR", "WARNING", "INFO"]
    assert list(_subparsers(parser)["diff"]._option_string_actions["--format"].choices) == ["text", "json", "sarif"]


def test_help_texts_mention_the_documented_options(parser):
    scan_help = " ".join(_subparsers(parser)["scan"].format_help().split())  # undo argparse line wrapping

    for token in ("--format", "--ai-review", "--fail-on", "INFO < WARNING < ERROR", "OPENAI_API_KEY"):
        assert token in scan_help
    # The one-line descriptions of diff and tui are shown by the top-level help.
    top_help = " ".join(parser.format_help().split())
    assert "Compares two versions of the same file" in top_help
    assert "interactive terminal interface (Textual)" in top_help
