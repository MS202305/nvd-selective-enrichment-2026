# scripts/config.py  --  snapshot 2026-06-29

import os
from datetime import date

# -- Collection date ---------------------------------------------
# All snapshot-dependent window ends derive from this value.
# Written to the run manifest for reproducibility.
FETCH_DATE = "2026-06-29"

# -- API configuration -------------------------------------------
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# -- Group definitions -------------------------------------------
GROUPS = {
    "group_A": {
        "start" : "2024-02-12",  # date NVD enrichment effectively stalled (fixed)
        "end"   : "2026-02-28",  # last day before 1 March 2026 (fixed)
        "status": "Deferred",    # API value; web-interface label is "Not Scheduled"
        "note"  : "Backlog: pre-policy, operational stall"
    },
    "group_B": {
        "start" : "2026-04-15",  # policy effective date (fixed)
        "end"   : "2026-06-29",  # collection date (snapshot-dependent)
        "status": "Deferred",    # API value; web-interface label is "Not Scheduled"
        "note"  : "Post-policy exclusion: deliberately out of scope"
    },
    "group_C": {
        "start" : "2024-02-12",  # date NVD enrichment effectively stalled (fixed)
        "end"   : "2026-06-29",  # collection date (snapshot-dependent)
        "status": "Analyzed",
        "note"  : "Reference population (NVD-enriched)"
    },
    "group_D": {
        "start" : "2026-03-01",  # 1 March inclusive (fixed)
        "end"   : "2026-04-14",  # last day before 15 April (fixed)
        "status": "Deferred",    # API value; web-interface label is "Not Scheduled"
        "note"  : "Transition window: reported separately"
    }
}

# -- Connection settings -----------------------------------------
REQUEST_TIMEOUT   = 120   # seconds; NVD can be slow to respond
RETRY_WAIT_BASE   = 60    # seconds; wait after a failed request

# -- NVD API settings --------------------------------------------
NVD_BASE_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE  = 2000
DELAY_WITH_KEY    = 0.6   # seconds
DELAY_WITHOUT_KEY = 6.0   # seconds

MAX_WINDOW_DAYS = 10

# -- Directories -------------------------------------------------
DIR_RAW       = "../data/raw"
DIR_PROCESSED = "../data/processed"
DIR_SNAPSHOTS = "../data/snapshots"

# -- Derived file paths ------------------------------------------
# Every analysis script takes its default paths from here, so the
# active config determines which snapshot is read; no script hard-codes
# a date or directory name.
NVD_GROUP_FILES = {g: f"{DIR_RAW}/nvd_{g}_{FETCH_DATE}.json" for g in GROUPS}
FILE_GROUP_A = NVD_GROUP_FILES["group_A"]
FILE_GROUP_B = NVD_GROUP_FILES["group_B"]
FILE_GROUP_C = NVD_GROUP_FILES["group_C"]
FILE_GROUP_D = NVD_GROUP_FILES["group_D"]

FILE_EPSS     = f"{DIR_SNAPSHOTS}/epss_scores-{FETCH_DATE}.csv"
FILE_KEV      = f"{DIR_SNAPSHOTS}/known_exploited_vulnerabilities_{FETCH_DATE}.json"
FILE_REGISTRY = f"{DIR_PROCESSED}/source_registry.json"

# -- Status values -----------------------------------------------
# API values are used throughout. Web-interface equivalents:
#   "Deferred" -> "Not Scheduled",  "Analyzed" -> "Analyzed"
STATUS_EXCLUDED  = "Deferred"
STATUS_REFERENCE = "Analyzed"


def group_window(group_name):
    """Return the (start, end) date pair for a group from GROUPS.
    Age-control windows are derived from here; scripts never hard-code dates."""
    g = GROUPS[group_name]
    return (date.fromisoformat(g["start"]), date.fromisoformat(g["end"]))

# -- Critical rule -----------------------------------------------
# The lastModified field is never used for grouping or filtering.
# The 17 June 2026 SSVC deployment rewrote lastModified for roughly 95%
# of all records, so it no longer reflects when a record last changed
# substantively. Group membership is determined solely by the published
# timestamp, which is set once at publication and never revised.
