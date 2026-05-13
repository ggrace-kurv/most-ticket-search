"""MOST2 Ticket Search — direct, no database.

Routes:
  GET /                                       Search form + paginated results
  GET /tickets/export.csv                     CSV export of the current filter set
  GET /api/tickets/<ticket_number>/comments   JSON: comments for one ticket
  GET /api/tickets/<ticket_number>/summary    JSON: Claude-generated summary
"""
import csv
import logging
from datetime import datetime
from io import StringIO
from typing import Any, Dict, List, Tuple
from urllib.parse import urlencode

from flask import Flask, Response, jsonify, render_template, request

import cache
import config
from claude_client import ClaudeError, _strip_html, answer_followup, summarize_ticket
from most2_client import MOST2Client, MOST2Error

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Single shared client. NTLM session is reused across requests; the client
# re-logs-in automatically when MOST2 returns 302/401.
_client = MOST2Client()


# Single-value filter keys. Multi-select filters (ownership_groups,
# service_reps) are pulled separately via getlist().
FILTER_KEYS = (
    "ticket_id",
    "merchant_id",
    "cn",
    "chain",
    "problem",
    "problem_group",
    "office",
    "status",
    "verification_status",
    "date_from",
    "date_to",
    "closed_from",
    "closed_to",
)

# Explicit map from our canonical column names → MOST2 response keys.
# Discovered by logging response.keys() on first successful query.
# `status` has no MOST2 field — it's derived from datetime presence.
FIELD_MAP = {
    "ticket_id": "TicketNumber",
    "merchant_id": "MerchantNumber",
    "cn": "CN",
    "dba": "Name",
    "problem": "ProblemType",
    "ownership_group": "OwnershipGroup",
    "office": "Office",
    "assigned_person": "CSRep",
    "opened_at": "OpenedDateTime",
    "closed_at": "ClosedDatetime",
    "last_updated": "UpdateDateTime",
    "age_days": "Age",
    "hold_count": "HoldCount",
    "sla_hours": "SLA_Hours",
    "escalation_level": "OpenEscalationLvl",
    "verification_status": "VerificationStatus",
    "plus_merchant": "PlusMerchant",
    "method": "Method",
    "last_comment": "LastCommentDate",
}

# Columns shown in the UI table and exported to CSV. `status` is derived.
EXPORT_COLUMNS = [
    "ticket_id",
    "cn",
    "merchant_id",
    "dba",
    "problem",
    "status",
    "ownership_group",
    "office",
    "assigned_person",
    "opened_at",
    "closed_at",
    "age_days",
    "last_comment",
]

# Display names that don't fit the auto title-cased "_".replace(" ").title()
# transform. Anything not listed falls back to that default in the template.
COLUMN_LABELS = {
    "ticket_id": "Ticket #",
    "merchant_id": "Merchant #",
    "cn": "CN",
    "dba": "DBA",
    "ownership_group": "Owner Grp",
    "assigned_person": "Service Rep",
    "opened_at": "Opened",
    "closed_at": "Closed",
    "last_comment": "Last Comment",
    "age_days": "Age (d)",
    "sla_hours": "SLA (h)",
}


def parse_filters(args) -> Tuple[Dict[str, Any], List[str], List[str]]:
    """Read recognized filters from request args.

    Returns (single_filters, ownership_groups, service_reps).
    Empty values are dropped. List filters use getlist().
    """
    out: Dict[str, Any] = {}
    for k in FILTER_KEYS:
        v = (args.get(k) or "").strip()
        if v:
            out[k] = v
    groups = [g for g in args.getlist("ownership_groups") if g]
    reps = [r for r in args.getlist("service_reps") if r]
    return out, groups, reps


def fetch_results(
    base_filters: Dict[str, Any],
    groups: List[str],
    reps: List[str],
) -> Tuple[List[Dict[str, Any]], str]:
    """Run one MOST2 search per (group, rep) combination, dedupe, return rows.

    Returns (rows, warning_message). Warning is empty string when nothing
    notable happened.
    """
    # Build the cartesian product. Use a sentinel single-element list when
    # one dimension is unselected so the caller still hits the endpoint once.
    group_axis = groups or [""]
    rep_axis = reps or [""]
    combos = [(g, r) for g in group_axis for r in rep_axis]

    if len(combos) > config.MAX_SEARCH_CALLS:
        return [], (
            f"Too many filter combinations ({len(combos)} > "
            f"{config.MAX_SEARCH_CALLS}). Narrow your selection."
        )

    # Status is sent upstream (so MOST2's 1000-row cap applies to relevant
    # tickets, not closed-history clutter). It's part of the cache key, so
    # changing status triggers a fresh fetch. Client-side filter_by_status
    # is kept as a safety net.
    status = base_filters.get("status", "")
    upstream_filters = base_filters
    cache_key = {**upstream_filters, "_groups": group_axis, "_reps": rep_axis}

    cached = cache.get(cache_key, config.SEARCH_CACHE_TTL)
    if cached is not None:
        filtered = filter_by_status(cached, status)
        logger.info(
            "cache hit (%d rows, %d after status=%s)",
            len(cached), len(filtered), status or "any",
        )
        return filtered, ""

    seen: set = set()
    merged: List[Dict[str, Any]] = []
    truncated_pairs: List[Tuple[str, str]] = []

    for group, rep in combos:
        per_call = {**upstream_filters}
        if group:
            per_call["ownership_group"] = group
        if rep:
            per_call["service_rep"] = rep
        rows = _client.search_tickets(per_call)
        if len(rows) >= 1000:
            truncated_pairs.append((group, rep))
        for row in rows:
            tid = row.get("TicketNumber")
            if tid in seen:
                continue
            seen.add(tid)
            merged.append(row)

    cache.put(cache_key, merged)
    filtered = filter_by_status(merged, status)
    logger.info(
        "cache miss → %d combos, %d rows (%d after status=%s) groups=%s reps=%s",
        len(combos), len(merged), len(filtered), status or "any", groups, reps,
    )

    warning = ""
    if truncated_pairs:
        labelled = [
            f"group={g or '(any)'} × rep={r or '(any)'}" for g, r in truncated_pairs
        ]
        warning = (
            f"{len(truncated_pairs)} of {len(combos)} upstream calls hit MOST2's "
            f"1000-row cap and were truncated: {'; '.join(labelled)}. "
            f"Add a date range or narrow problem/office filters on those slices."
        )
    return filtered, warning


def lookup(row: Dict[str, Any], canonical_key: str) -> Any:
    """Pull a canonical column value from a MOST2 row using FIELD_MAP."""
    if canonical_key == "status":
        return derive_status(row)
    most2_key = FIELD_MAP.get(canonical_key)
    if most2_key is None:
        return ""
    value = row.get(most2_key)
    if value is None:
        return ""
    return value


def derive_status(row: Dict[str, Any]) -> str:
    """MOST2 doesn't ship a Status column. Infer it from the date fields."""
    if (row.get("ClosedDatetime") or "").strip():
        return "Closed"
    if (row.get("HoldDateTime") or "").strip():
        return "Hold"
    return "Open"


_SORTABLE_COLUMNS = {
    "ticket_id", "merchant_id", "cn", "dba", "problem", "status",
    "ownership_group", "office", "assigned_person", "opened_at",
    "closed_at", "age_days", "last_comment",
}
_NUMERIC_SORT_COLUMNS = {"ticket_id", "merchant_id", "cn", "age_days"}


def sort_rows(
    rows: List[Dict[str, Any]],
    col: str,
    direction: str,
) -> List[Dict[str, Any]]:
    """Sort rows by a canonical column name. Numeric columns parse as int;
    everything else falls back to lower-case string compare. Date columns
    are stored as YYYY-MM-DD HH:MM:SS strings, which sort lexicographically
    in chronological order — no special handling needed."""
    if col not in _SORTABLE_COLUMNS:
        col = "opened_at"
        direction = "desc"
    reverse = direction == "desc"

    if col in _NUMERIC_SORT_COLUMNS:
        def key(r):
            v = lookup(r, col)
            try:
                return int(v)
            except (ValueError, TypeError):
                return 0
    else:
        def key(r):
            return str(lookup(r, col) or "").lower()

    return sorted(rows, key=key, reverse=reverse)


_STATUS_PREDICATES = {
    "B": lambda s: s in ("Open", "Hold"),
    "O": lambda s: s == "Open",
    "H": lambda s: s == "Hold",
    "C": lambda s: s == "Closed",
}


def filter_by_status(rows: List[Dict[str, Any]], status: str) -> List[Dict[str, Any]]:
    """Drop rows whose derived status doesn't match the requested filter."""
    pred = _STATUS_PREDICATES.get(status)
    if pred is None:
        return rows
    return [r for r in rows if pred(derive_status(r))]


@app.route("/")
def search():
    filters, groups, reps = parse_filters(request.args)
    page = max(int(request.args.get("page", 1)), 1)
    per_page = int(request.args.get("per_page", 100))
    if per_page not in (25, 50, 100, 200, 500):
        per_page = 100

    sort_col = request.args.get("sort", "opened_at")
    sort_dir = request.args.get("dir", "desc")
    if sort_col not in _SORTABLE_COLUMNS:
        sort_col = "opened_at"
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"

    submitted = (
        bool(filters) or bool(groups) or bool(reps) or "submitted" in request.args
    )
    rows: List[Dict[str, Any]] = []
    error = None
    warning = ""

    if submitted:
        try:
            rows, warning = fetch_results(filters, groups, reps)
        except MOST2Error as e:
            error = f"MOST2 error: {e}"
            logger.error(error)
        except Exception as e:
            error = f"Search failed: {e}"
            logger.exception(error)

    rows = sort_rows(rows, sort_col, sort_dir)

    # Merge any ProblemType values seen in this result set into the dropdown
    # options. Keeps the picker current as MOST2 adds new problem types
    # without requiring a config.py edit. Unknown types are also logged so
    # they can be promoted into the canonical list.
    seen_problem_types = {
        (r.get("ProblemType") or "").strip() for r in rows
    } - {""}
    canonical = set(config.PROBLEM_TYPES)
    extras = sorted(seen_problem_types - canonical, key=str.lower)
    if extras:
        logger.info(
            "problem types present in results but missing from config.PROBLEM_TYPES: %s",
            extras,
        )
    merged_problem_types = sorted(canonical | seen_problem_types, key=str.lower)

    total = len(rows)
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    visible = rows[start : start + per_page]

    base_args = [(k, v) for k, v in request.args.items(multi=True) if k != "page"]

    def page_url(n: int) -> str:
        return "?" + urlencode(base_args + [("page", n)])

    def sort_url(col: str) -> str:
        """URL to apply when clicking a column header. Toggles direction
        if the column is already active; otherwise switches to asc."""
        new_dir = "desc" if (sort_col == col and sort_dir == "asc") else "asc"
        kept = [
            (k, v) for k, v in request.args.items(multi=True)
            if k not in ("sort", "dir", "page")
        ]
        return "?" + urlencode(kept + [("sort", col), ("dir", new_dir)])

    return render_template(
        "search.html",
        filters=filters,
        selected_groups=set(groups),
        selected_reps=set(reps),
        all_groups=config.OWNERSHIP_GROUPS,
        problem_groups=config.PROBLEM_GROUPS,
        problem_types=merged_problem_types,
        team_reps=config.TEAM_REPS,
        service_reps=config.SERVICE_REPS,
        submitted=submitted,
        error=error,
        warning=warning,
        tickets=visible,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        columns=EXPORT_COLUMNS,
        column_labels=COLUMN_LABELS,
        lookup=lookup,
        page_url=page_url,
        sort_url=sort_url,
        sort_col=sort_col,
        sort_dir=sort_dir,
        export_query=urlencode(base_args),
    )


@app.route("/tickets/export.csv")
def export_csv():
    filters, groups, reps = parse_filters(request.args)
    try:
        rows, _ = fetch_results(filters, groups, reps)
    except Exception as e:
        logger.exception("CSV export failed")
        return Response(f"Export failed: {e}", status=500)

    columns = EXPORT_COLUMNS + ["comments"]
    buf = StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(columns)
    total = len(rows)
    for i, row in enumerate(rows):
        comments_text = _fetch_comments_for_export(row.get("TicketNumber"))
        out = [_csv_value(lookup(row, c)) for c in EXPORT_COLUMNS]
        out.append(comments_text)
        writer.writerow(out)
        if (i + 1) % 50 == 0:
            logger.info("CSV export progress: %d/%d tickets", i + 1, total)

    filename = f"tickets-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    logger.info("CSV export: %d rows (with comments)", total)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _fetch_comments_for_export(ticket_number: Any) -> str:
    """Per-ticket comment fetch for CSV export.

    Returns a plain-text transcript, oldest-first. No redaction —
    this download is internal-only. Per-ticket failures are logged
    and stubbed so one bad ticket doesn't abort the whole export.
    """
    if not ticket_number:
        return ""
    try:
        notes = _client.get_ticket_comments(ticket_number)
    except Exception as e:
        logger.warning("comments fetch failed for %s: %s", ticket_number, e)
        return f"[error fetching comments: {e}]"
    if not notes:
        return ""
    blocks = []
    for n in reversed(notes):  # MOST2 returns newest-first
        body = _strip_html(n.get("Comments") or "")
        if not body:
            continue
        # Flatten newlines: Excel mis-renders embedded \n in CSV cells as
        # extra rows when opened via double-click. Collapse whitespace runs
        # into single spaces so each ticket stays on one CSV row.
        body = " ".join(body.split())
        when = n.get("DateAdded") or "(no date)"
        who = n.get("AddedBy") or n.get("CSRep") or "unknown"
        status = n.get("Status") or ""
        header = f"{when} | {who}"
        if status:
            header += f" | status={status}"
        blocks.append(f"[{header}] {body}")
    return " ;; ".join(blocks)


@app.route("/api/tickets/<ticket_number>/comments")
def api_ticket_comments(ticket_number):
    """Return the comment/note records for one ticket as JSON."""
    try:
        notes = _client.get_ticket_comments(ticket_number)
    except MOST2Error as e:
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        logger.exception("comments fetch failed for %s", ticket_number)
        return jsonify({"error": str(e)}), 500
    return jsonify({"ticket_number": ticket_number, "notes": notes})


@app.route("/api/tickets/<ticket_number>/summary")
def api_ticket_summary(ticket_number):
    """Return a Claude-generated summary of the ticket's comment thread.

    Cached per ticket for SUMMARY_CACHE_TTL seconds. The cache key
    includes the comment count so adding a new note invalidates the
    summary on next view.
    """
    try:
        notes = _client.get_ticket_comments(ticket_number)
    except MOST2Error as e:
        return jsonify({"error": f"MOST2 error: {e}"}), 502
    except Exception as e:
        logger.exception("comments fetch failed for %s", ticket_number)
        return jsonify({"error": str(e)}), 500

    cache_key = {"_type": "summary", "ticket": str(ticket_number), "n": len(notes)}
    cached = cache.get(cache_key, config.SUMMARY_CACHE_TTL)
    if cached is not None:
        return jsonify({
            "ticket_number": ticket_number,
            "summary": cached[0]["summary"] if cached else "",
            "note_count": len(notes),
            "cached": True,
        })

    try:
        summary = summarize_ticket(ticket_number, notes)
    except ClaudeError as e:
        logger.error("Claude summary failed for %s: %s", ticket_number, e)
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        logger.exception("summary failed for %s", ticket_number)
        return jsonify({"error": str(e)}), 500

    cache.put(cache_key, [{"summary": summary}])
    return jsonify({
        "ticket_number": ticket_number,
        "summary": summary,
        "note_count": len(notes),
        "cached": False,
    })


@app.route("/api/tickets/<ticket_number>/ask", methods=["POST"])
def api_ticket_ask(ticket_number):
    """Answer a follow-up question about a ticket using its comment thread.

    Stateless: the client sends the prior summary + conversation history,
    we re-fetch the comments and re-prompt Claude. Comments are pulled
    fresh each call so newly-added notes are reflected immediately.
    """
    payload = request.get_json(silent=True) or {}
    question = (payload.get("question") or "").strip()
    summary = (payload.get("summary") or "").strip()
    history = payload.get("history") or []

    if not question:
        return jsonify({"error": "Missing 'question'."}), 400
    if len(question) > 2000:
        return jsonify({"error": "Question too long (max 2000 characters)."}), 400
    if not isinstance(history, list) or len(history) > 30:
        return jsonify({"error": "Invalid or too-long conversation history."}), 400
    cleaned_history: List[Dict[str, str]] = []
    for m in history:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        content = m.get("content")
        if role in ("user", "assistant") and isinstance(content, str) and content.strip():
            cleaned_history.append({"role": role, "content": content.strip()[:4000]})

    try:
        notes = _client.get_ticket_comments(ticket_number)
    except MOST2Error as e:
        return jsonify({"error": f"MOST2 error: {e}"}), 502
    except Exception as e:
        logger.exception("comments fetch failed for %s", ticket_number)
        return jsonify({"error": str(e)}), 500

    try:
        answer = answer_followup(ticket_number, notes, summary, cleaned_history, question)
    except ClaudeError as e:
        logger.error("Claude follow-up failed for %s: %s", ticket_number, e)
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        logger.exception("follow-up failed for %s", ticket_number)
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "ticket_number": ticket_number,
        "answer": answer,
        "note_count": len(notes),
    })


def _csv_value(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    return str(v)


@app.route("/health")
def health():
    return {"ok": True, "session": bool(_client.session_id)}


if __name__ == "__main__":
    print(f"Starting MOST2 Ticket Search on http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
