from C2Client.assistant_agent.presentation import render_assistant_answer
from C2Client.assistant_agent.skills.panel import render_run_details
from C2Client.console_style import append_console_block, append_console_spacing
from PyQt6.QtWidgets import QTextBrowser


def test_answer_highlights_first_paragraph_and_keeps_tables_readable():
    rendered = render_assistant_answer("Three listeners are relevant.\n\n| Listener | State |\n|---|---|\n| a | active |")
    assert "font-weight:bold" in rendered
    assert "<table width=\"100%\"" in rendered
    assert "Three listeners are relevant." in rendered
    assert "active" in rendered
    assert "<script" not in render_assistant_answer("<script>alert(1)</script>")


def test_answer_preserves_shell_quotes_in_code(qtbot):
    editor = QTextBrowser()
    qtbot.addWidget(editor)
    command = "python3 -c 'print(\"hello\")'"
    append_console_block(editor, "Analysis:", render_assistant_answer(f"`{command}`"), rich_message=True)
    assert command in editor.toPlainText()
    assert "&#x27;" not in editor.toPlainText()
    assert "&quot;" not in editor.toPlainText()


def test_rich_answer_cannot_carry_a_list_or_margins_into_later_turns(qtbot):
    editor = QTextBrowser()
    qtbot.addWidget(editor)
    append_console_block(editor, "Analysis:", render_assistant_answer(
        "First answer.\n\n1. Do this.\n2. Do that."), rich_message=True)
    append_console_spacing(editor)
    append_console_block(editor, "User:", "Next request")
    append_console_spacing(editor)
    append_console_block(editor, "Analysis:", render_assistant_answer(
        "Summary.\n\nAnother paragraph."), rich_message=True)
    append_console_spacing(editor)
    append_console_block(editor, "User:", "Following request")

    blocks = []
    block = editor.document().begin()
    while block.isValid():
        blocks.append(block)
        block = block.next()
    for block in blocks:
        if "Next request" in block.text() or "Following request" in block.text() \
                or "[user]" in block.text():
            assert block.textList() is None
            assert block.blockFormat().topMargin() == 0
            assert block.blockFormat().bottomMargin() <= 4


def test_skill_report_separates_summary_findings_and_evidence():
    run = {"run_id": "run-123456", "status": "completed", "steps": [],
           "report": {"outcome": "partial", "summary": "Transfer incomplete.",
                      "observations": [{"source_id": "job-1", "finding": "First destination succeeded."}],
                      "limitations": ["Second destination failed."], "evidence": []}}
    compact = render_run_details(run)
    assert "PARTIAL" in compact
    assert "What I found" in compact and "What remains uncertain" in compact
    assert "job-1" not in compact
    assert "Execution details" not in compact
    assert "Execution details" in render_run_details(run, show_evidence=True)


def test_skill_report_uses_wrapping_prose_instead_of_table_rows(qtbot):
    finding = ("Interface addresses include loopback 127.0.0.1/::1, Wi-Fi interface "
               "wlp0s20f3 at 192.168.1.140 with global IPv6 addresses, gpd0 at "
               "10.79.29.246, and several Docker bridge networks.")
    run = {"run_id": "run-123456", "status": "completed", "steps": [],
           "report": {"summary": "The selected beacon has several network interfaces and routes.",
                      "observations": [{"finding": finding}],
                      "limitations": ["The connection path remains uncertain."], "evidence": []}}
    rendered = render_run_details(run)
    assert "<table" not in rendered
    assert "<li" in rendered

    editor = QTextBrowser()
    qtbot.addWidget(editor)
    editor.resize(440, 300)
    editor.setHtml(rendered)
    editor.show()
    editor.repaint()
    assert finding in editor.toPlainText()
    block = editor.document().findBlockByNumber(3)
    assert block.layout().lineCount() > 1
    assert editor.horizontalScrollBar().maximum() == 0
