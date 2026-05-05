# MOST2 Ticket Search

Direct, no-database ticket search against MOST2. Search → display → CSV export.
Single-process Flask app; in-memory cache of the last query so paging through
results doesn't re-hit MOST2.

## Quick start

```bash
cd most-ticket-search
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env       # then edit with real creds
python app.py              # http://127.0.0.1:5003
```

## Files

- `app.py` — Flask routes (`/`, `/tickets/export.csv`, `/health`)
- `most2_client.py` — NTLM client, login + ticket search
- `cache.py` — TTL keyed on filter hash
- `config.py` — env loader
- `templates/search.html` — form + results in one page

## You must do this before search will work

`MOST2Client.search_tickets` posts to `/WebService.asmx/ticket_search_load_grid`,
but **the exact field names this endpoint expects are unknown** — no existing
code in the parent `most-dashboard` project ever called it. The current
payload in `most2_client.py` is a best guess and will likely return `[]` or
500 until adjusted.

To fix:

1. Open MOST2 in a browser, log in, run a real search on `TicketSearch.aspx`.
2. DevTools → Network → click the POST to `ticket_search_load_grid`.
3. Copy the request payload (Headers tab → "Request payload", or right-click →
   "Copy as cURL").
4. Compare the field names to the dict in `most2_client.py::search_tickets`
   and adjust. Likely culprits:
   - `TicketID` vs `ticketId` vs `txtTicketID`
   - Date format (`MM/DD/YYYY` vs ISO)
   - `Status` value: single char (`O`/`H`/`C`) vs full word (`Open`)
   - Pagination keys (`PageSize`/`PageNumber` vs `pageSize`/`pageIndex`)
5. Also note the response field names — `lookup()` in `app.py` does
   case-insensitive matching, but if MOST2 uses unexpected names (e.g.
   `merch_id` instead of any flavor of `merchant_id`), update `EXPORT_COLUMNS`
   in `app.py`.

## Caching

`SEARCH_CACHE_TTL` (default 600s) is process-local. **Don't run multiple
gunicorn workers** — each would have its own cache and hammer MOST2 on every
page click. For dev / single-user internal use, `python app.py` is the right
launcher.

## Pagination

The UI paginates locally from cached results. Upstream pagination is bounded
by `EMS_MAX_PAGES * EMS_PAGE_SIZE` (default 10,000 rows). If you regularly
need more, raise `EMS_MAX_PAGES` — but be aware each page is a serial NTLM
POST and the search will slow down linearly.

## CSV export

The "Download CSV" button on the search page exports the current filter set's
full result set (not just the visible page). Hitting the cap logs a warning;
results may be silently truncated upstream.
