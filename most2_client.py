"""Thin MOST2 client. NTLM auth + ticket search + ticket comments.

Pattern (verified against existing MOST2Integration):
  1. GET /TicketSearch.aspx -> 200 with redirect URL containing (S(<id>))
  2. POST /(S(<id>))/WebService.asmx/<endpoint> with JSON body
  3. Response is {"d": "<json string>"} -> json.loads(data["d"])
"""
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from requests_ntlm import HttpNtlmAuth

import config

logger = logging.getLogger(__name__)

_BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    ),
}


class MOST2Error(Exception):
    """Raised when MOST2 returns an unexpected response."""


class MOST2Client:
    def __init__(self):
        self.session = requests.Session()
        username = config.USERNAME or ""
        # NTLM expects domain\user; if .env username has no backslash, prepend fdc\
        if username and "\\" not in username:
            username = f"fdc\\{username}"
        self.username = username
        self.session.auth = HttpNtlmAuth(username, config.PASSWORD)
        self.session_id: Optional[str] = None
        self.last_login = 0.0

    def login(self) -> None:
        """Get a fresh session id from MOST2."""
        url = f"{config.EMS_BASE_URL}/TicketSearch.aspx"
        resp = self.session.get(url, headers=_BROWSER_HEADERS, timeout=30)
        if resp.status_code != 200:
            raise MOST2Error(f"Login failed: HTTP {resp.status_code}")
        if "(S(" not in resp.url:
            raise MOST2Error("Login response missing session id")
        self.session_id = resp.url.split("(S(")[1].split("))")[0]
        self.last_login = time.time()
        logger.info("MOST2 login OK, session=%s", self.session_id[:8] + "...")

    def _ensure_session(self) -> None:
        if not self.session_id:
            self.login()

    def _post(self, path: str, payload: Dict[str, Any]) -> Any:
        """POST to a WebService.asmx method. Returns parsed contents of the 'd' field."""
        self._ensure_session()
        url = f"{config.EMS_BASE_URL}/(S({self.session_id})){path}"
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
        }
        resp = self.session.post(url, headers=headers, json=payload, timeout=60)
        # MOST2 occasionally invalidates session ids; retry once on 302/401.
        if resp.status_code in (302, 401):
            logger.warning("MOST2 session expired, re-logging in")
            self.login()
            url = f"{config.EMS_BASE_URL}/(S({self.session_id})){path}"
            resp = self.session.post(url, headers=headers, json=payload, timeout=60)

        if not resp.ok:
            # ASP.NET ASMX returns the actual reason in the body (often JSON
            # with a "Message" / "ExceptionType" / "StackTrace" field, or a
            # plain HTML error page). Surface it so we can diagnose payload
            # mismatches without needing a HAR capture.
            body = resp.text or ""
            snippet = body[:1500]
            logger.error(
                "MOST2 %s -> HTTP %d\n  payload sent: %s\n  response body: %s",
                path, resp.status_code, json.dumps(payload), snippet,
            )
            raise MOST2Error(
                f"HTTP {resp.status_code} from {path}. "
                f"Body (first 1500 chars): {snippet}"
            )

        data = resp.json()
        if "d" not in data:
            raise MOST2Error(f"Unexpected response shape: {list(data.keys())}")
        inner = data["d"]
        # The 'd' field is usually a JSON-encoded string, but MOST2 sometimes
        # returns it already-decoded. Handle both.
        if isinstance(inner, str):
            return json.loads(inner) if inner else []
        return inner

    # ------------------------------------------------------------------
    # Ticket search
    # ------------------------------------------------------------------
    def search_tickets(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search MOST2 tickets. Returns the raw ticket dicts.

        Payload shape verified against a captured DevTools request. Field
        names are ASP.NET WebForms control IDs (`ddl*` = dropdown,
        `txt*` = text, `cb*` = checkbox/combo). Every field must be
        present — the endpoint 500s if any are missing.

        `filters` keys (UI-side, all optional):
          ticket_id, merchant_id, cn, problem, office, status,
          ownership_group, date_from, date_to  (dates as YYYY-MM-DD)
        """
        # Map our app's internal status codes to MOST2's wire codes.
        # App: B=Open+Hold (default), O=Open, H=Hold, C=Closed, A=Any.
        # MOST2: O, H, C, OH=Open & On Hold, B=Any.
        # Sending status upstream lets MOST2 apply its 1000-row cap to
        # *relevant* tickets, drastically reducing truncation when reps
        # have lots of closed history.
        _MOST2_STATUS = {"B": "OH", "O": "O", "H": "H", "C": "C", "A": "B"}
        status_value = _MOST2_STATUS.get(filters.get("status", ""), "OH")

        payload = {
            "ddlServiceRep": filters.get("service_rep", ""),
            "ddlGroup": filters.get("ownership_group", ""),
            "cbProblemType": filters.get("problem", ""),
            "ddlProbCatID": filters.get("problem_group", ""),
            "txtTixNum": filters.get("ticket_id", ""),
            "txtOffice": filters.get("office", ""),
            "txtCN": filters.get("cn", ""),
            "txtDBA": "",
            "txtMID": filters.get("merchant_id", ""),
            "txtOpenFrom": _to_us_date(filters.get("date_from", "")),
            "txtOpenTo": _to_us_date(filters.get("date_to", "")),
            "txtClosedFrom": _to_us_date(filters.get("closed_from", "")),
            "txtClosedTo": _to_us_date(filters.get("closed_to", "")),
            "dtDate": "",
            "ddlTixStatus": status_value,
            "escalationLvl": "",
            "txtChain": filters.get("chain", ""),
            "ddlVerificationStatus": filters.get("verification_status", ""),
        }

        result = self._post(config.EMS_SEARCH_PATH, payload)
        if not isinstance(result, list):
            logger.warning("Unexpected ticket-search result type: %s", type(result))
            return []

        # On the first successful response, log the column names so we can
        # tune EXPORT_COLUMNS / lookup() in app.py without guessing.
        if result and not getattr(self, "_logged_columns", False):
            logger.info("MOST2 response columns: %s", sorted(result[0].keys()))
            self._logged_columns = True

        # Decode wire-format dates so callers don't have to.
        for row in result:
            for date_key in ("OpenedDateTime", "ClosedDatetime", "HoldDateTime",
                             "UpdateDateTime", "LastCommentDate"):
                if date_key in row:
                    row[date_key] = parse_aspnet_date(row[date_key])

        return result

    def get_ticket_comments(self, ticket_number: Any) -> List[Dict[str, Any]]:
        """Fetch all note records for a single ticket.

        Endpoint: /WebService.asmx/ticket_info_load_grid
        Payload:  {"strTicketNumber": "<ticket number as string>"}

        Response records contain: STC_ID, DateAdded, OwnershipGroup,
        AddedBy, ProblemType, CSRep, Comments (HTML), EscalationLvl,
        Status, DocExist, FileName, RiskOnly.
        """
        payload = {"strTicketNumber": str(ticket_number) if ticket_number else ""}
        result = self._post(config.EMS_INFO_PATH, payload)
        if not isinstance(result, list):
            logger.warning("Unexpected ticket_info result type: %s", type(result))
            return []
        for note in result:
            note["DateAdded"] = parse_aspnet_date(note.get("DateAdded"))
        return result


def _to_us_date(iso_or_blank: str) -> str:
    """Convert YYYY-MM-DD (HTML date input) → MM/DD/YYYY (MOST2 expectation)."""
    if not iso_or_blank:
        return ""
    parts = iso_or_blank.split("-")
    if len(parts) == 3:
        y, m, d = parts
        return f"{m.zfill(2)}/{d.zfill(2)}/{y}"
    return iso_or_blank  # already formatted, or unrecognized — pass through


_ASPNET_DATE_RE = re.compile(r"/Date\((-?\d+)([+-]\d{4})?\)/")


_MIN_REAL_DATE_MS = 631152000000  # 1990-01-01 00:00:00 UTC


def parse_aspnet_date(value: Any) -> str:
    """Convert ASP.NET `/Date(milliseconds)/` strings to YYYY-MM-DD HH:MM:SS.

    Returns "" for "no date set" sentinels — most commonly .NET's
    DateTime.MinValue (`/Date(-62135596800000)/` → year 0001) and SQL
    Server's `1900-01-01` placeholder. Any timestamp before 1990 is
    treated as unset; real ticket dates are decades after that.

    Returns the original value if it doesn't match `/Date(...)/` — MOST2
    occasionally returns plain strings for some fields.
    """
    if not value:
        return ""
    if not isinstance(value, str):
        return str(value)
    m = _ASPNET_DATE_RE.match(value)
    if m:
        ms = int(m.group(1))
        if ms < _MIN_REAL_DATE_MS:
            return ""
        try:
            dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            return value
    # Plain ISO string (e.g. "1900-01-01T00:00:00") — also check for
    # sentinel dates and normalize formatting.
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.year < 1990:
            return ""
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


