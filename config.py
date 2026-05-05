"""Environment-driven config. All values read once at import."""
import os
from dotenv import load_dotenv

load_dotenv()


def _read_username():
    """Read USERNAME from .env preserving the literal backslash in domain\\user.

    python-dotenv handles this correctly in modern versions, but the original
    project's MOST2Integration explicitly read .env line-by-line as a workaround.
    Mirrored here for parity.
    """
    try:
        with open(".env", "r") as f:
            for line in f:
                if line.startswith("USERNAME="):
                    return line.split("=", 1)[1].strip()
    except FileNotFoundError:
        pass
    return os.getenv("USERNAME", "")


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

# My team — used to populate the rep checkbox group in the UI. Edit here
# (or override TEAM_REPS in .env as a comma-separated list) to change it.
_team_env = os.getenv("TEAM_REPS", "")
TEAM_REPS = [r.strip() for r in _team_env.split(",") if r.strip()] or [
    "Greg Grace",
    "Brent Smith",
    "Mark McGowan",
    "Jeffrey Scherger",
    "Michael Morell",
]

# Ownership groups — copied from the original most-dashboard project.
# Used to populate the group multi-select.
OWNERSHIP_GROUPS = [
    "Customer Service",
    "eCommerce",
    "Equipment/Technical",
    "Risk",
    "Leasing",
    "InsideSales",
    "Gift",
    "Accounting",
    "Programming",
    "Agents",
    "Collections",
    "Install",
    "Install PC",
    "Shipping",
    "Pricing",
    "Partners",
    "Underwriting",
    "Customer Retention",
    "Processing",
    "MaxxPay",
    "PCI",
    "PLUS",
    "Special Projects",
    "Total Touch",
    "Transaction/Billing",
    "Web",
    "WHO",
]

FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", "5003"))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
