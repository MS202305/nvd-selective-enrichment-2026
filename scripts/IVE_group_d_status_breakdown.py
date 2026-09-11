#!/usr/bin/env python3
'''Status breakdown of the transition window (Group D). Counts every record
 in the Group D snapshot by its vulnStatus and reports each status as a
 count and a share of the group. No status filtering is applied here: the
 point is to show how the 45-day transition window is distributed across
 statuses at the data-collection date.'''

import json
import argparse
from collections import Counter

from config import (
    FILE_GROUP_D,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--group-d", default=FILE_GROUP_D)
    a = ap.parse_args()

    with open(a.group_d, encoding="utf-8") as f:
        records = [v["cve"] for v in json.load(f)["vulnerabilities"]]

    total = len(records)
    counts = Counter(cve.get("vulnStatus", "(missing)") for cve in records)

    print(f"Group D  (transition window)")
    print(f"  total records: {total}")
    print(f"  status breakdown (status | count | % of group):")
    for status, cnt in counts.most_common():
        pct = round(cnt / total * 100, 2) if total else 0.0
        print(f"    {status:<16} {cnt:>6}  {pct:>6}%")

    # Grouping that matches the paper: Analyzed, Deferred, and everything else.
    analyzed = counts.get("Analyzed", 0)
    deferred = counts.get("Deferred", 0)
    other = total - analyzed - deferred
    pct = lambda x: round(x / total * 100, 2) if total else 0.0
    print()
    print(f"  Analyzed : {analyzed:>6}  ({pct(analyzed)}%)")
    print(f"  Deferred : {deferred:>6}  ({pct(deferred)}%)")
    print(f"  Other    : {other:>6}  ({pct(other)}%)")


if __name__ == "__main__":
    main()
