#!/usr/bin/env python3
'''Status transition matrix between two NVD snapshots.

For every CVE that appears in BOTH snapshots (same group file), records its
vulnStatus at each snapshot and tabulates the transitions. Also reports
records present in only one snapshot, which indicates either late
publication (new in the second snapshot) or a crawl gap.

Answers, for the 2026-06-29 -> 2026-09-01 comparison:
  * where did the Group A records that left "Deferred" go?
  * where did the Group C records that left "Analyzed" go?
  * is either crawl missing records that the other one has?

Both snapshots are read from config.DIR_RAW. --new-date defaults to
config.FETCH_DATE; --old-date defaults to 2026-06-29.

Usage (from scripts/):
  python status_transitions.py --group A
  python status_transitions.py --group C --pub-end 2026-02-28
  python status_transitions.py --group D
'''

import json
import argparse
from collections import Counter, defaultdict

from config import DIR_RAW, FETCH_DATE


def load_status(path):
    """{cve_id: (vulnStatus, published)} for one group file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = {}
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cid = cve.get("id")
        if cid:
            out[cid] = (cve.get("vulnStatus", "(missing)"),
                        cve.get("published", "")[:10])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-date", default="2026-06-29")
    ap.add_argument("--new-date", default=FETCH_DATE)
    ap.add_argument("--raw-dir", default=DIR_RAW)
    ap.add_argument("--group", required=True, choices=["A", "B", "C", "D"])
    ap.add_argument("--pub-end", default=None,
                    help="Optional: only consider CVEs published on or before "
                         "this date (YYYY-MM-DD). Use 2026-06-29 when comparing "
                         "Group C so the extended window does not inflate 'new'.")
    ap.add_argument("--show-ids", type=int, default=20,
                    help="How many CVE ids to list per transition of interest.")
    a = ap.parse_args()

    old = load_status(f"{a.raw_dir}/nvd_group_{a.group}_{a.old_date}.json")
    new = load_status(f"{a.raw_dir}/nvd_group_{a.group}_{a.new_date}.json")

    if a.pub_end:
        old = {k: v for k, v in old.items() if v[1] <= a.pub_end}
        new = {k: v for k, v in new.items() if v[1] <= a.pub_end}

    old_ids, new_ids = set(old), set(new)
    both = old_ids & new_ids
    only_old = old_ids - new_ids
    only_new = new_ids - old_ids

    print(f"Group {a.group}: {a.old_date} -> {a.new_date}"
          + (f"  (published <= {a.pub_end})" if a.pub_end else ""))
    print(f"  records in old snapshot : {len(old_ids):>7}")
    print(f"  records in new snapshot : {len(new_ids):>7}")
    print(f"  in both                 : {len(both):>7}")
    print(f"  only in old (LOST)      : {len(only_old):>7}  <- crawl gap if > 0")
    print(f"  only in new             : {len(only_new):>7}")
    print()

    # Transition matrix over the overlap
    trans = Counter((old[c][0], new[c][0]) for c in both)
    statuses = sorted({s for pair in trans for s in pair})

    print("  Transition matrix (rows = old status, cols = new status):")
    w = max(len(s) for s in statuses) + 2
    print("  " + " " * w + "".join(f"{s:>{w}}" for s in statuses))
    for s_old in statuses:
        row = "".join(f"{trans.get((s_old, s_new), 0):>{w}}" for s_new in statuses)
        print(f"  {s_old:<{w}}{row}")
    print()

    changed = {c for c in both if old[c][0] != new[c][0]}
    print(f"  records whose status changed: {len(changed)} / {len(both)}"
          f"  ({len(changed)/len(both)*100:.3f}%)")
    print()

    # Detail on the transitions that matter for the paper
    by_pair = defaultdict(list)
    for c in changed:
        by_pair[(old[c][0], new[c][0])].append(c)
    for pair, ids in sorted(by_pair.items(), key=lambda kv: -len(kv[1])):
        print(f"  {pair[0]} -> {pair[1]}: {len(ids)}")
        for cid in sorted(ids)[:a.show_ids]:
            print(f"      {cid}  (published {old[cid][1]})")
        if len(ids) > a.show_ids:
            print(f"      ... and {len(ids) - a.show_ids} more")
        print()

    if only_old:
        print(f"  LOST records (in old, missing from new) - first {a.show_ids}:")
        for cid in sorted(only_old)[:a.show_ids]:
            print(f"      {cid}  {old[cid][0]}  (published {old[cid][1]})")
        print()


if __name__ == "__main__":
    main()
