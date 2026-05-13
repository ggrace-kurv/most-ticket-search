"""Environment-driven config. All values read once at import."""
import logging
import os
import secrets
import sys

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def _read_username():
    """Read USERNAME from .env preserving the literal backslash in domain\\user.

    Optional now that per-user login is the primary auth path. Kept so
    health-check / smoke-test scripts that set USERNAME in .env continue
    to work without a login form.
    """
    try:
        with open(".env", "r") as f:
            for line in f:
                if line.startswith("USERNAME="):
                    return line.split("=", 1)[1].strip()
    except FileNotFoundError:
        pass
    return os.getenv("USERNAME", "")


# Optional fallback creds. Left in place so /health and CI scripts can
# warm up without an interactive login, but unused for serving any
# logged-in user — each user authenticates with their own MOST2 account.
USERNAME = _read_username()
PASSWORD = os.getenv("PASSWORD", "")

EMS_BASE_URL = os.getenv("EMS_BASE_URL", "https://most2.emscorporate.com").rstrip("/")
EMS_SEARCH_PATH = os.getenv("EMS_SEARCH_PATH", "/WebService.asmx/ticket_search_load_grid")
EMS_INFO_PATH = os.getenv("EMS_INFO_PATH", "/WebService.asmx/ticket_info_load_grid")
EMS_TICKET_STATUS = os.getenv("EMS_TICKET_STATUS", "O")

SEARCH_CACHE_TTL = int(os.getenv("SEARCH_CACHE_TTL", "600"))
SUMMARY_CACHE_TTL = int(os.getenv("SUMMARY_CACHE_TTL", "3600"))

# Multi-select: hard cap on how many MOST2 calls one search can fan out to.
# Combinations = len(selected_reps) * len(selected_groups). Each call is a
# serial NTLM POST so the search slows linearly. Adjust here if needed.
MAX_SEARCH_CALLS = int(os.getenv("MAX_SEARCH_CALLS", "10"))

# My team — drives the "My team" quick-pick on the search form. Override
# via TEAM_REPS in .env (comma-separated) if needed. Each entry must also
# appear in SERVICE_REPS below or the quick-pick will silently miss it.
_team_env = os.getenv("TEAM_REPS", "")
TEAM_REPS = [r.strip() for r in _team_env.split(",") if r.strip()] or [
    "Greg Grace",
    "Brent Smith",
    "Mark McGowan",
    "Jeffrey Scherger",
    "Michael Morell",
]

# All service reps — verbatim from the ddlServiceRep <select> on
# TicketSearch.aspx, in MOST2's own (alphabetical) order.
SERVICE_REPS = [
    "Alaicia Hart",
    "Alan Colon",
    "Alexandra Robles",
    "Anna Wilson",
    "Ashlyn Murray",
    "Bob Bland",
    "Brandon Washington",
    "Brent Smith",
    "Caitlin Flynn",
    "Cedric Mize",
    "Ciara Henry",
    "Cody Brown",
    "Curtis Grenville",
    "David Teasley",
    "Delmeta Carrothers",
    "Diamonaire Pittman",
    "Gary Btest",
    "Genesis Velazquez",
    "Greg Grace",
    "Heather Niles",
    "Hussein Alnuaimi",
    "Jade Chapman",
    "Jeffrey Scherger",
    "Jim Connor",
    "John Dorsey",
    "Jon Butinski",
    "Kasiri Mixon",
    "Katherine Ruber",
    "Kim Dennis",
    "Kristine Park",
    "Kyle Doershuk",
    "Laura Stolp",
    "Lynn Fioritto",
    "Malik Penn",
    "Marion Unartel",
    "Mark McGowan",
    "Markon Montgomery",
    "Merrell W Sheehan",
    "Mi'Shauna Swain",
    "Michael Morell",
    "Nathan Khaimov",
    "Orie Dean",
    "Paul Weber",
    "Payge Swanson",
    "Renee Goldoff",
    "Richard Young",
    "Samantha Romero",
    "Scott Litman",
    "Shada Pearson",
    "test vmtest",
    "Tony Stephens",
    "Valeria Izquieta",
]

# Ownership groups — verbatim from the ddlGroup <select> on TicketSearch.aspx,
# in MOST2's own order. Don't add Problem-Group labels here (Equipment/Technical,
# MaxxPay, PCI, PLUS, Special Projects, Total Touch, Transaction/Billing, Web,
# WHO) — those belong to ddlProbGroup and silently return 0 rows when used as
# owner-group filters.
OWNERSHIP_GROUPS = [
    "Customer Retention",
    "Processing",
    "Customer Service",
    "Risk",
    "Leasing",
    "InsideSales",
    "Gift",
    "Accounting",
    "eCommerce",
    "Programming",
    "Agents",
    "Collections",
    "Install",
    "Shipping",
    "Pricing",
    "Partners",
    "Underwriting",
    "Install PC",
]

# Problem groups — verbatim from the ddlProbGroup <select> on TicketSearch.aspx,
# in MOST2's own order. Values are numeric IDs (not labels) — MOST2 expects the
# id on the wire. "Customer Service" appears in BOTH this list and OWNERSHIP_GROUPS;
# they're distinct fields.
PROBLEM_GROUPS = [
    {"id": "22", "label": "Customer Service"},
    {"id": "23", "label": "eCommerce"},
    {"id": "1", "label": "Equipment/Technical"},
    {"id": "36", "label": "Escalated Problem"},
    {"id": "24", "label": "Gift Card"},
    {"id": "25", "label": "Inside Sales"},
    {"id": "35", "label": "Install"},
    {"id": "26", "label": "Leasing"},
    {"id": "39", "label": "MaxxPay"},
    {"id": "31", "label": "PCI"},
    {"id": "38", "label": "PLUS"},
    {"id": "27", "label": "Processing"},
    {"id": "33", "label": "Programming"},
    {"id": "32", "label": "Retention"},
    {"id": "28", "label": "Risk"},
    {"id": "30", "label": "Shipping"},
    {"id": "37", "label": "Special Projects"},
    {"id": "41", "label": "Total Touch"},
    {"id": "2", "label": "Transaction/Billing"},
    {"id": "44", "label": "Web"},
    {"id": "7", "label": "WHO"},
]

# Problem types — discovered from a sample of MOST2 ticket data (status=B
# and status=C, ~1000 rows each). Sorted case-insensitively. Some labels
# contain en-dash (–) vs hyphen (-) — both forms exist in MOST2 and must
# be preserved verbatim. To refresh: hit /tickets/export.csv for status=B
# and status=C, aggregate distinct values from the `problem` column, sort.
PROBLEM_TYPES = [
    "Add - Amex",
    "Add - Contact Person",
    "Add - Debit",
    "ADM",
    "Administrative - Completed",
    "Amex Compliance",
    "Bank Account",
    "Call Backs",
    "Call backs",
    "Call Tag Issued",
    "Call tag sent",
    "Cancel - All services",
    "Cancel - Gateway/Wireless",
    "Cancel – Waiver Request",
    "CC# (request for credit card number)",
    "Change notice",
    "Chargebacks/retrievals",
    "Close - Non DP Merchant",
    "Discover Noncompliance",
    "Dual Pricing Rate Adjust",
    "E-commerce – Fraud Settings",
    "eCommerce - Install/training",
    "Email Address Change",
    "EMV TPP Upgrade",
    "EMV Upgrade - PROPOSED",
    "Escalated - Retention",
    "Escalated – KART",
    "Gateway",
    "Gift Card",
    "Gift cards",
    "Hardware – MaxxPay",
    "Install - Other",
    "Install – MaxxPay",
    "Install/training",
    "Inventory / Menu – MaxxPay",
    "KurvPay - Build",
    "KurvPay - Financial",
    "KurvPay - Integration",
    "KurvPay - technical",
    "MCC Change",
    "Merchant Number Change",
    "Network Issues (LAN) – MaxxPay",
    "Other",
    "Paper Statement",
    "Password reset/Login problems",
    "Paysley - Technical",
    "PC Rate Review",
    "PCI",
    "PCI Refund",
    "POS / VAR",
    "PreInstall - MaxxPay",
    "Programming",
    "Rate review",
    "Rate Review - $",
    "Rate Review - %",
    "Rate Review - Signed",
    "RB/QD Errors",
    "Refund",
    "Refund - cxl fee",
    "Rejected Transactions",
    "ReOpen Account",
    "Research",
    "Returned Fee",
    "Returned TPP Equipment",
    "Risk Issue - Merchant being contacted",
    "Risk Issue - Merchant funds held",
    "Sales - Change of Ownership",
    "Send 1099K",
    "Send Cancel Form",
    "Service call",
    "Shipped, not yet delivered",
    "Software – MaxxPay",
    "Statement/billing",
    "Terminal",
    "Terminal problems",
    "termination/closed",
    "TIN & Name mismatch callback",
    "Transaction/Batch/Deposit",
    "TT - MISC SW",
    "TT - Phone HW",
    "TT - Phone SW",
    "TT - Registration",
    "TT-Sales",
    "Valor - Add Services",
    "Verification",
    "Waiting on Senior Mgmt Approval",
]

FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", "5003"))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"


def _resolve_secret_key() -> str:
    """SECRET_KEY drives Flask's session cookie signing.

    Production must set SECRET_KEY in .env. If missing in debug mode we
    generate an ephemeral one (sessions die at restart, which is fine
    for local dev); in non-debug mode we refuse to start with a default
    or placeholder value, since reusing "change-me" would let anyone
    forge a session cookie for any user.
    """
    val = os.getenv("SECRET_KEY", "")
    if val and val != "change-me":
        return val
    if FLASK_DEBUG:
        logger.warning(
            "SECRET_KEY not set; generating an ephemeral key. "
            "Sessions will not survive process restart."
        )
        return secrets.token_hex(32)
    print(
        "FATAL: SECRET_KEY is unset or set to the default placeholder. "
        "Generate one with `python -c 'import secrets; print(secrets.token_hex(32))'` "
        "and add it to .env before starting the app.",
        file=sys.stderr,
    )
    sys.exit(1)


SECRET_KEY = _resolve_secret_key()

# Per-user MOST2 sessions are stored server-side via flask-session, so
# only an opaque session id rides in the cookie. The session file holds
# the user's MOST2 password — restrict the directory's filesystem perms.
SESSION_FILE_DIR = os.getenv("SESSION_FILE_DIR", "/tmp/most-ticket-search-sessions")
# Auto-logout after this many seconds of inactivity. Default 8h covers a
# work day without forcing a re-login mid-task.
SESSION_LIFETIME_SECONDS = int(os.getenv("SESSION_LIFETIME_SECONDS", str(60 * 60 * 8)))
# Set to "false" only for local HTTP development. Production must be HTTPS.
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() != "false"
