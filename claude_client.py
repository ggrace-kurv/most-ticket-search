"""Thin wrapper around the `claude` CLI for ticket summarization.

Uses whichever Claude Code auth is configured on the host (subscription,
API key fallback, etc.). No Anthropic SDK dependency, no API key required.

Run with `claude --print` for non-interactive single-shot output. Haiku
is plenty for summarization and keeps the round-trip fast.
"""
import html
import logging
import re
import shutil
import subprocess
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

CLAUDE_BINARY = "claude"
CLAUDE_MODEL = "claude-haiku-4-5"
CLAUDE_TIMEOUT_SECS = 60


class ClaudeError(Exception):
    """Raised when the claude CLI fails or is not available."""


def _strip_html(s: str) -> str:
    """Convert MOST2 comment HTML to plain text without pulling in bleach/bs4."""
    if not s:
        return ""
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.IGNORECASE)
    s = re.sub(r"</p>\s*<p>", "\n\n", s, flags=re.IGNORECASE)
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


# ---- Redaction --------------------------------------------------------
# Best-effort PII / CHD scrubbing before any text leaves this process.
# Regex-based redaction is NOT a compliance boundary — a determined leaker
# can defeat it with formatting tricks. This is defense-in-depth only.
# Apply only to comment bodies; internal-employee metadata (CSRep,
# AddedBy, OwnershipGroup) is preserved so summaries remain useful.

# 13–19 contiguous digits, optionally separated by spaces or dashes in
# groups of 4 (or 4-6-5 for Amex). Word boundaries on each side.
_PAN_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_EIN_RE = re.compile(r"(?<!\d)\d{2}-\d{7}(?!\d)")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# US phone — must have at least one separator (parens, dash, dot, space)
# or a +1 prefix. Pure 10-digit runs are far more often merchant IDs in
# this corpus than phone numbers, so we deliberately don't match those.
_PHONE_RE = re.compile(
    r"(?<!\d)(?:"
    r"\+1[\s.-]?\d{3}[\s.-]?\d{3}[\s.-]?\d{4}"      # +1 555-123-4567
    r"|\(\d{3}\)\s?\d{3}[\s.-]?\d{4}"               # (555) 123-4567
    r"|\d{3}[\s.-]\d{3}[\s.-]\d{4}"                 # 555-123-4567 / 555.123.4567
    r")(?!\d)"
)
# Magnetic stripe track data — these patterns are almost never benign.
_TRACK1_RE = re.compile(r"%[A-Z]?\d{1,19}\^[^?]{2,26}\^[^?]+\?")
_TRACK2_RE = re.compile(r";\d{1,19}=\d{4,}\?")


def _luhn_ok(digits: str) -> bool:
    """Standard Luhn checksum. Used to drop false-positive PAN matches."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _redact_pan(match: re.Match) -> str:
    raw = match.group(0)
    digits = re.sub(r"\D", "", raw)
    if 13 <= len(digits) <= 19 and _luhn_ok(digits):
        return "[REDACTED-PAN]"
    return raw  # not a valid card number — leave it (e.g. order ID, MID)


def redact(text: str) -> str:
    """Scrub PII / CHD from comment-body text before sending externally."""
    if not text:
        return ""
    # Track data first (before PAN regex eats the digits).
    text = _TRACK1_RE.sub("[REDACTED-TRACK1]", text)
    text = _TRACK2_RE.sub("[REDACTED-TRACK2]", text)
    text = _PAN_RE.sub(_redact_pan, text)
    text = _SSN_RE.sub("[REDACTED-SSN]", text)
    text = _EIN_RE.sub("[REDACTED-EIN]", text)
    text = _EMAIL_RE.sub("[REDACTED-EMAIL]", text)
    text = _PHONE_RE.sub("[REDACTED-PHONE]", text)
    return text


def _format_notes(notes: List[Dict[str, Any]]) -> str:
    """Render note records in chronological order as a plain-text transcript."""
    # MOST2 returns newest-first; reverse for natural narrative order.
    chronological = list(reversed(notes))
    blocks = []
    for n in chronological:
        when = n.get("DateAdded") or "(no date)"
        who = n.get("AddedBy") or n.get("CSRep") or "unknown"
        group = n.get("OwnershipGroup") or ""
        problem = n.get("ProblemType") or ""
        status = n.get("Status") or ""
        header_bits = [when, who]
        if group:
            header_bits.append(group)
        if problem:
            header_bits.append(problem)
        if status:
            header_bits.append(f"status={status}")
        body = redact(_strip_html(n.get("Comments") or ""))
        if not body:
            continue
        blocks.append(f"[{' | '.join(header_bits)}]\n{body}")
    return "\n\n".join(blocks)


_PROMPT_TEMPLATE = """You are summarizing an internal service ticket for a payments processor.
Read the comments (oldest first) and write a concise summary in 100-150 words covering:
- what the merchant needs / the problem
- what has been done so far
- the current status and likely next step
- any blockers or notable context

Use plain prose. Do not include the ticket number or restate that it's a summary.

Ticket #{ticket_number}

Comments:
{comments}
"""


def summarize_ticket(ticket_number: Any, notes: List[Dict[str, Any]]) -> str:
    """Run the claude CLI against a ticket's comment thread and return the summary text."""
    if shutil.which(CLAUDE_BINARY) is None:
        raise ClaudeError(
            f"`{CLAUDE_BINARY}` not found on PATH. Install Claude Code or "
            f"adjust CLAUDE_BINARY in claude_client.py."
        )

    transcript = _format_notes(notes)
    if not transcript:
        return "No comments on this ticket yet."

    prompt = _PROMPT_TEMPLATE.format(
        ticket_number=ticket_number,
        comments=transcript,
    )

    try:
        result = subprocess.run(
            [CLAUDE_BINARY, "--print", "--model", CLAUDE_MODEL],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=CLAUDE_TIMEOUT_SECS,
        )
    except subprocess.TimeoutExpired:
        raise ClaudeError(f"Claude CLI timed out after {CLAUDE_TIMEOUT_SECS}s")
    except FileNotFoundError as e:
        raise ClaudeError(f"Failed to invoke claude: {e}")

    if result.returncode != 0:
        stderr_snippet = (result.stderr or "").strip()[:500]
        raise ClaudeError(f"claude CLI exited {result.returncode}: {stderr_snippet}")

    summary = (result.stdout or "").strip()
    if not summary:
        raise ClaudeError("claude CLI returned empty output")
    logger.info("summarized ticket %s (%d notes → %d chars)", ticket_number, len(notes), len(summary))
    return summary
