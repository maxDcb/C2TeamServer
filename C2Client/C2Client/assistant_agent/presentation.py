"""Readable, safe HTML for assistant answers in the conversation console."""

from __future__ import annotations

import html
import re

import markdown


def render_assistant_answer(message: str) -> str:
    # Escape model-supplied HTML while preserving Markdown structure.
    body = markdown.markdown(html.escape(message, quote=False), extensions=["fenced_code", "tables"])
    body = re.sub(r"<h([1-6])>",
                  lambda match: f'<h{match.group(1)} style="color:#7cd4fd; margin:10px 0 4px;">',
                  body)
    body = body.replace("<table>", '<table width="100%" cellspacing="0" cellpadding="6" '
                        'style="background:#14212b; border:1px solid #263241;">')
    body = body.replace("<th>", '<th style="color:#7cd4fd; background:#173039; text-align:left;">')
    body = body.replace("<td>", '<td style="border-bottom:1px solid #263241;">')
    body = body.replace("<pre>", '<pre style="white-space:pre-wrap; background:#111c25; '
                        'color:#d0d5dd; padding:9px; margin:4px 0;">')
    body = body.replace("<blockquote>", '<blockquote style="color:#fdb022; background:#1e262b; '
                        'margin:4px 0; padding:7px;">')
    # The first paragraph is the glanceable answer. Subsequent paragraphs carry detail.
    body = body.replace("<p>", '<p style="color:#f2f4f7; font-size:14px; font-weight:bold; '
                        'margin:0 0 4px;">', 1)
    body = body.replace("<p>", '<p style="margin:0 0 4px;">')
    return f'<div style="color:#d0d5dd; font-family:sans-serif;">{body}</div>'
