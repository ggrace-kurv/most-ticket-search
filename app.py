"""MOST2 Ticket Search — direct, no database.

Routes:
  GET  /                                       Search form + paginated results
  GET  /login                                  Show login form
  POST /login                                  Validate creds + start session
  GET  /logout                                 Clear session, return to /login
  GET  /tickets/export.csv                     CSV export of the current filter set
  GET  /api/tickets/<ticket_number>/comments   JSON: comments for one ticket
  GET  /api/tickets/<ticket_number>/summary    JSON: Claude-generated summary
  POST /api/tickets/<ticket_number>/ask        JSON: follow-up question
  GET  /health                                 Liveness probe (no auth)
"""
import csv
import logging
import os
import secrets
import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from functools import wraps
from io import StringIO
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

from flask import (
    Flask, Response, jsonify, redirect, render_template,
    request, session, url_for,
)
from flask_session import Session

import auth_crypto
import cache
import config
from claude_client import ClaudeError, _strip_html, answer_followup, summarize_ticket
from most2_client import MOST2AuthError, MOST2Client, MOST2Error

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Server-side sessions via flask-session: an opaque session id rides
# in the cookie; everything else (including the encrypted MOST2
# password) lives in SESSION_FILE_DIR. Even with at-rest encryption,
# we want the directory itself to be unreadable by other local users.
os.makedirs(config.SESSION_FILE_DIR, exist_ok=True)
try:
    os.chmod(config.SESSION_FILE_DIR, 0o700)
except OSError:
    pass  # already restricted, or fs doesn't support chmod (eg. /mnt/c)


def _enforce_session_dir_perms():
    """Refuse to start in production if SESSION_FILE_DIR is too open.

    On a POSIX filesystem the chmod above lands us at 0o700. On WSL
    /mnt/c paths the chmod is a no-op and the directory effectively
    inherits 0o777. Even with encrypted password fields the dir name
    listing leaks who logged in and when, and a misconfigured
    SECRET_KEY-shared deploy could let someone read passwords.

    Strict by default in non-debug mode. Set SESSION_PERMS_STRICT=false
    to override (eg. for the existing /mnt/c WSL deployment) — at-rest
    encryption is doing most of the work anyway.
    """
    try:
        mode = os.stat(config.SESSION_FILE_DIR).st_mode & 0o777
    except OSError:
        return
    if not (mode & 0o077):
        return
    msg = (
        f"SESSION_FILE_DIR {config.SESSION_FILE_DIR} has mode {oct(mode)} — "
        f"group/other bits are set. Passwords are encrypted at rest, but the "
        f"directory should still be 0700 to avoid leaking session metadata."
    )
    if config.FLASK_DEBUG:
        logger.warning("%s (OK for debug)", msg)
        return
    strict = os.getenv("SESSION_PERMS_STRICT", "true").lower() != "false"
    if not strict:
        logger.error("%s — SESSION_PERMS_STRICT=false, continuing anyway", msg)
        return
    print(
        f"FATAL: {msg} Move to a POSIX-compliant filesystem "
        f"(eg. /var/lib/most-ticket-search/sessions) or set "
        f"SESSION_PERMS_STRICT=false in .env to override.",
        file=sys.stderr,
    )
    sys.exit(1)


_enforce_session_dir_perms()
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = config.SESSION_FILE_DIR
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=config.SESSION_LIFETIME_SECONDS)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE
app.config["SESSION_USE_SIGNER"] = True
Session(app)


# Defence-in-depth headers applied to every response. CSP is the
# load-bearing one: it constrains where scripts / styles / images can
# load from so a successful HTML injection (eg. a comment that slips
# past DOMPurify) can't reach an attacker-controlled script. We allow
# inline scripts and styles because the dashboard template has many
# onclick= handlers and a large inline <style> block; tightening that
# to nonces is a future hardening pass tracked in the audit notes.
_BASE_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none';"
)


@app.after_request
def _set_security_headers(response):
    response.headers.setdefault("Content-Security-Policy", _BASE_CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    # Belt-and-suspenders for frame-ancestors above; older browsers and
    # some scanners still look at X-Frame-Options.
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


# Per-user MOST2 clients. Building a MOST2Client costs nothing, but
# reusing the underlying requests.Session lets us reuse the NTLM handshake
# and the (S(...)) session id across calls — which matters when a user
# clicks through 5+ pages in a minute. Keyed by a per-login UUID stored
# in session["user_id"]; cleared on logout and on auth failure.
#
# Bounded LRU: without this, users who close their tab without signing
# out would leak a MOST2Client (and its in-memory password) into the
# dict forever, until process restart. We sweep two ways: by idle TTL
# matching the cookie lifetime, and by hard count if traffic spikes.
_CLIENTS_MAX = int(os.getenv("MAX_CACHED_CLIENTS", "500"))
_CLIENTS_TTL_SECONDS = config.SESSION_LIFETIME_SECONDS
_clients: "OrderedDict[str, Tuple[MOST2Client, float]]" = OrderedDict()
_clients_lock = threading.Lock()


def _is_safe_next_url(next_url: str) -> bool:
    """Decide whether a ?next=… value is safe to redirect to after login.

    The previous check was `startswith("/") and not startswith("//")`.
    That rejects scheme-relative URLs but misses backslash variants
    that some browsers normalize (eg. `/\\evil.com/path`) and control
    characters used in header smuggling. urlparse drops both.
    """
    if not next_url:
        return False
    if any(c in next_url for c in ("\\", "\r", "\n", "\t")):
        return False
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        return False
    return next_url.startswith("/") and not next_url.startswith("//")


def _check_same_origin() -> Optional[Tuple[Any, int]]:
    """Reject state-changing requests whose Origin doesn't match host.

    SameSite=Lax already blocks most cross-site POSTs, but a
    misconfigured reverse proxy or a future relaxation could let one
    through; the Origin check is the textbook CSRF defence and is
    essentially free. Same-origin requests from older clients that
    omit Origin are allowed — they're indistinguishable from server-
    generated requests.
    """
    origin = request.headers.get("Origin", "")
    if not origin:
        return None
    expected = urlparse(request.host_url).netloc.lower()
    actual = urlparse(origin).netloc.lower()
    if actual != expected:
        logger.warning(
            "Rejected cross-origin %s %s: Origin=%s expected=%s",
            request.method, request.path, origin, expected,
        )
        return jsonify({"error": "Origin mismatch."}), 403
    return None


def _log_internal_error(prefix: str, exc: Exception) -> str:
    """Log a full traceback with a fresh correlation id and return a
    user-safe message that only references the id.

    Use this anywhere we'd otherwise dump str(e) into a response body —
    a Python exception's str form can include path fragments, internal
    function names, and library internals that are recon material for
    an attacker. The correlation id makes it easy to find the real
    detail in the server logs without exposing it on the wire.
    """
    cid = secrets.token_hex(8)
    logger.exception("[%s] %s: %s", cid, prefix, exc)
    return f"{prefix} (ref {cid}). Server logs have details."


def _sweep_stale_clients_locked(now: float) -> None:
    """Evict clients whose last_used is older than _CLIENTS_TTL_SECONDS.

    Caller must hold _clients_lock. The OrderedDict is maintained in
    LRU order (front = oldest), so peeking the head and popping until
    we hit a fresh entry is enough — no full scan needed.
    """
    while _clients:
        oldest_uid = next(iter(_clients))
        _, last_used = _clients[oldest_uid]
        if now - last_used > _CLIENTS_TTL_SECONDS:
            _clients.popitem(last=False)
            logger.info(
                "evicted idle client user_id=%s (idle > %ds)",
                oldest_uid, _CLIENTS_TTL_SECONDS,
            )
        else:
            break


def _get_client() -> Optional[MOST2Client]:
    """Return the MOST2Client for the current user, building it if necessary.

    Reads creds from the Flask session (filesystem-backed). Returns None
    when there's no logged-in user — callers should already have run
    @require_login, so this is mainly a safety net for the /health route.
    """
    user_id = session.get("user_id")
    username = session.get("most2_username")
    enc_password = session.get("most2_password_enc")
    if not (user_id and username and enc_password):
        return None
    try:
        password = auth_crypto.decrypt_password(enc_password)
    except auth_crypto.InvalidToken:
        # Session ciphertext can't be decrypted with the current SECRET_KEY
        # — usually means SECRET_KEY was rotated, or the session file was
        # tampered. Either way, treat as "needs to log in again".
        logger.warning(
            "Stored password failed to decrypt for user_id=%s — forcing re-login",
            user_id,
        )
        return None

    now = time.time()
    with _clients_lock:
        _sweep_stale_clients_locked(now)
        if user_id in _clients:
            client, _ = _clients[user_id]
            # Refresh recency: move to the back (most-recent end) of the
            # LRU and bump last_used so _sweep_stale_clients_locked treats
            # this user as active.
            _clients.move_to_end(user_id)
            _clients[user_id] = (client, now)
            return client
        client = MOST2Client(username, password)
        if len(_clients) >= _CLIENTS_MAX:
            evicted_uid, _ = _clients.popitem(last=False)
            logger.warning(
                "client cache at cap (%d) — evicted LRU user_id=%s",
                _CLIENTS_MAX, evicted_uid,
            )
        _clients[user_id] = (client, now)
        return client


def _drop_client() -> None:
    """Forget the in-memory MOST2Client for the current session.

    Called on logout and when MOST2 rejects mid-session credentials.
    Safe to call when there's no client cached.
    """
    user_id = session.get("user_id")
    if not user_id:
        return
    with _clients_lock:
        _clients.pop(user_id, None)


def require_login(view):
    """Redirect anonymous users to /login (HTML) or return 401 JSON (APIs).

    The split keeps `fetch()` calls in the frontend from following a 302
    into the login page's HTML — they get a clean 401 they can react to.
    """
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("most2_username") or not session.get("most2_password_enc"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Not authenticated."}), 401
            # Preserve the originally-requested URL (path + query) so the
            # post-login redirect lands the user back where they were.
            target = request.full_path.rstrip("?") if request.query_string else request.path
            return redirect(url_for("login", next=target))
        return view(*args, **kwargs)
    return wrapper


@app.errorhandler(MOST2AuthError)
def _handle_most2_auth_error(err: MOST2AuthError):
    """Drop the user's session if MOST2 rejects their creds mid-flight.

    The most2_client distinguishes auth failures (MOST2AuthError) from
    other upstream errors (MOST2Error) precisely so this handler fires
    only when the user genuinely needs to log in again, not on every
    transient 5xx.
    """
    logger.warning("MOST2 auth failure for session user_id=%s: %s",
                   session.get("user_id"), err)
    _drop_client()
    session.clear()
    if request.path.startswith("/api/"):
        return jsonify({"error": "Your MOST2 session expired. Please sign in again."}), 401
    return redirect(url_for("login"))


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
    client: MOST2Client,
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
    # Per-user cache namespace: two reps querying the same filters can see
    # different rows because MOST2's results respect their own permissions
    # and "My tickets" defaults. Keep their caches separate.
    cache_key = {
        **upstream_filters,
        "_groups": group_axis,
        "_reps": rep_axis,
        "_user": client.username_bare,
    }

    cached = cache.get(cache_key, config.SEARCH_CACHE_TTL)
    if cached is not None:
        filtered = filter_by_status(cached, status)
        logger.info(
            "cache hit user=%s (%d rows, %d after status=%s)",
            client.username_bare, len(cached), len(filtered), status or "any",
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
        rows = client.search_tickets(per_call)
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
        "cache miss user=%s → %d combos, %d rows (%d after status=%s) groups=%s reps=%s",
        client.username_bare, len(combos), len(merged), len(filtered),
        status or "any", groups, reps,
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
@require_login
def search():
    client = _get_client()
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
            rows, warning = fetch_results(client, filters, groups, reps)
        except MOST2AuthError:
            raise  # let the global handler clear the session and redirect
        except MOST2Error as e:
            # MOST2Error.__str__ is already sanitized (correlation id only)
            error = f"MOST2 error: {e}"
            logger.error(error)
        except Exception as e:
            error = _log_internal_error("Search failed", e)

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
        current_user=client.username_bare if client else "",
        current_user_full_name=session.get("full_name", ""),
        my_tickets_url=_build_my_tickets_url(),
    )


def _build_my_tickets_url() -> str:
    """URL the 'My Tickets' button hits.

    Pre-fills service_reps=<your display name>, status=B (Open+Hold),
    and submitted=1 so the page runs the search on load. Empty when we
    don't have a parsed display name (the button is hidden in that case).
    """
    name = session.get("full_name", "")
    if not name:
        return ""
    qs = urlencode([
        ("service_reps", name),
        ("status", "B"),
        ("submitted", "1"),
    ])
    return url_for("search") + "?" + qs


@app.route("/tickets/export.csv")
@require_login
def export_csv():
    client = _get_client()
    filters, groups, reps = parse_filters(request.args)
    try:
        rows, _ = fetch_results(client, filters, groups, reps)
    except MOST2AuthError:
        raise
    except Exception as e:
        return Response(_log_internal_error("CSV export failed", e), status=500)

    columns = EXPORT_COLUMNS + ["comments"]
    buf = StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(columns)
    total = len(rows)
    for i, row in enumerate(rows):
        comments_text = _fetch_comments_for_export(client, row.get("TicketNumber"))
        out = [_csv_value(lookup(row, c)) for c in EXPORT_COLUMNS]
        out.append(comments_text)
        writer.writerow(out)
        if (i + 1) % 50 == 0:
            logger.info("CSV export progress: %d/%d tickets", i + 1, total)

    filename = f"tickets-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    logger.info("CSV export user=%s: %d rows (with comments)", client.username_bare, total)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _fetch_comments_for_export(client: MOST2Client, ticket_number: Any) -> str:
    """Per-ticket comment fetch for CSV export.

    Returns a plain-text transcript, oldest-first. No redaction —
    this download is internal-only. Per-ticket failures are logged
    and stubbed so one bad ticket doesn't abort the whole export.
    """
    if not ticket_number:
        return ""
    try:
        notes = client.get_ticket_comments(ticket_number)
    except MOST2AuthError:
        raise
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
@require_login
def api_ticket_comments(ticket_number):
    """Return the comment/note records for one ticket as JSON."""
    client = _get_client()
    try:
        notes = client.get_ticket_comments(ticket_number)
    except MOST2AuthError:
        raise
    except MOST2Error as e:
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({
            "error": _log_internal_error(f"Comments fetch failed for ticket {ticket_number}", e),
        }), 500
    return jsonify({"ticket_number": ticket_number, "notes": notes})


@app.route("/api/tickets/<ticket_number>/summary")
@require_login
def api_ticket_summary(ticket_number):
    """Return a Claude-generated summary of the ticket's comment thread.

    Cached per ticket for SUMMARY_CACHE_TTL seconds. The cache key
    includes the comment count so adding a new note invalidates the
    summary on next view.
    """
    client = _get_client()
    try:
        notes = client.get_ticket_comments(ticket_number)
    except MOST2AuthError:
        raise
    except MOST2Error as e:
        return jsonify({"error": f"MOST2 error: {e}"}), 502
    except Exception as e:
        return jsonify({
            "error": _log_internal_error(f"Comments fetch failed for ticket {ticket_number}", e),
        }), 500

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
        return jsonify({
            "error": _log_internal_error(f"Summary failed for ticket {ticket_number}", e),
        }), 500

    cache.put(cache_key, [{"summary": summary}])
    return jsonify({
        "ticket_number": ticket_number,
        "summary": summary,
        "note_count": len(notes),
        "cached": False,
    })


@app.route("/api/tickets/<ticket_number>/ask", methods=["POST"])
@require_login
def api_ticket_ask(ticket_number):
    """Answer a follow-up question about a ticket using its comment thread.

    Stateless: the client sends the prior summary + conversation history,
    we re-fetch the comments and re-prompt Claude. Comments are pulled
    fresh each call so newly-added notes are reflected immediately.
    """
    # Only state-changing endpoint in the app — defence-in-depth Origin
    # check on top of SameSite=Lax cookies. (Comments / Summary are GETs
    # and don't need it.)
    origin_block = _check_same_origin()
    if origin_block is not None:
        return origin_block

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

    client = _get_client()
    try:
        notes = client.get_ticket_comments(ticket_number)
    except MOST2AuthError:
        raise
    except MOST2Error as e:
        return jsonify({"error": f"MOST2 error: {e}"}), 502
    except Exception as e:
        return jsonify({
            "error": _log_internal_error(f"Comments fetch failed for ticket {ticket_number}", e),
        }), 500

    try:
        answer = answer_followup(ticket_number, notes, summary, cleaned_history, question)
    except ClaudeError as e:
        logger.error("Claude follow-up failed for %s: %s", ticket_number, e)
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({
            "error": _log_internal_error(f"Follow-up failed for ticket {ticket_number}", e),
        }), 500

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
    """Liveness probe. Public — intentionally tells external callers
    nothing beyond "the process is up". Earlier versions returned the
    count of cached clients, which gave an unauthenticated attacker
    timing data about active sessions; removed."""
    return {"ok": True}


@app.route("/login", methods=["GET", "POST"])
def login():
    """Per-user MOST2 login.

    Validates by attempting a real MOST2 login() before storing the
    credentials in the server-side session. We never write the password
    to disk in plaintext outside of the flask-session file (which lives
    under SESSION_FILE_DIR with 0700 perms).
    """
    if session.get("most2_username") and session.get("most2_password_enc"):
        # Already signed in — bounce straight to the dashboard. Lets users
        # bookmark /login without it looking broken.
        return redirect(url_for("search"))

    error = None
    username = ""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_url = (request.form.get("next") or "").strip()

        if not username or not password:
            error = "Username and password are required."
        else:
            try:
                # Build the client and force a login() so we surface bad
                # creds *before* storing anything in the session.
                client = MOST2Client(username, password)
                client.login()
            except MOST2AuthError as e:
                error = str(e)
            except MOST2Error as e:
                error = f"Could not reach MOST2: {e}"
            except Exception as e:
                logger.exception("login failed for %s", username)
                error = f"Unexpected error during login: {e}"
            else:
                # Success — issue a brand-new session id (cheap defence
                # against session-fixation) and stash creds + the live client.
                session.clear()
                user_id = secrets.token_urlsafe(24)
                session.permanent = True
                session["user_id"] = user_id
                session["most2_username"] = username
                # Encrypted at rest in the flask-session file so a
                # disk-only attacker can't read it without also having
                # SECRET_KEY. See auth_crypto for the threat model.
                # NTLM still requires the live password in memory while
                # the user is active (held in MOST2Client + HttpNtlmAuth)
                # — that's residual exposure we can't eliminate without
                # changing protocols upstream.
                session["most2_password_enc"] = auth_crypto.encrypt_password(password)
                # Cached so "My Tickets" can pre-fill the service-rep filter
                # without a fresh GET of /TicketSearch.aspx on every request.
                session["full_name"] = client.full_name
                with _clients_lock:
                    if len(_clients) >= _CLIENTS_MAX:
                        evicted_uid, _ = _clients.popitem(last=False)
                        logger.warning(
                            "client cache at cap (%d) — evicted LRU user_id=%s on login",
                            _CLIENTS_MAX, evicted_uid,
                        )
                    _clients[user_id] = (client, time.time())
                logger.info("user logged in: %s", client.username_bare)
                # Only allow same-origin relative paths — _is_safe_next_url
                # rejects schemes, netlocs, and backslash/control-char
                # tricks that some browsers normalize past simple startswith
                # checks.
                if _is_safe_next_url(next_url):
                    return redirect(next_url)
                return redirect(url_for("search"))

    # GET, or POST with errors: show the form again.
    return render_template(
        "login.html",
        error=error,
        username=username,
        next_url=request.values.get("next", ""),
    )


@app.route("/logout", methods=["POST"])
def logout():
    """Drop the cached MOST2 client and clear the Flask session.

    POST-only because a GET logout is a CSRF vector: an attacker who
    can lure a logged-in rep to visit a page they control could include
    `<img src="/logout">` and forcibly sign them out. SameSite=Lax
    blocks cross-site POSTs, so requiring POST closes that hole.
    """
    user = session.get("most2_username")
    _drop_client()
    session.clear()
    if user:
        logger.info("user logged out: %s", user)
    return redirect(url_for("login"))


if __name__ == "__main__":
    print(f"Starting MOST2 Ticket Search on http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
