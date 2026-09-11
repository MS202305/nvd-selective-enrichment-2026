#!/usr/bin/env python3
''' Cross-retrieval consistency check for one snapshot date.

 Groups A, B and D are retrieved as sub-windows, Group C as the full
 period; the same CVE therefore appears in two independent retrievals
 made some minutes apart. This script compares vulnStatus across the two
 retrievals and reports records present in only one of them, mirroring
 the check described in Section III.C of the paper.'''

import json
import argparse
from collections import Counter

from config import FILE_GROUP_A, FILE_GROUP_B, FILE_GROUP_C, FILE_GROUP_D, FETCH_DATE


def load(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = {}
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cid = cve.get("id")
        if cid:
            out[cid] = (cve.get("vulnStatus", "(missing)"), cve.get("published", ""))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show-ids", type=int, default=20)
    a = ap.parse_args()

    sub = {}
    for name, path in (("A", FILE_GROUP_A), ("B", FILE_GROUP_B), ("D", FILE_GROUP_D)):
        for cid, rec in load(path).items():
            sub[cid] = (name,) + rec
    full = load(FILE_GROUP_C)

    sub_ids, full_ids = set(sub), set(full)
    both = sub_ids & full_ids
    only_sub = sub_ids - full_ids
    only_full = full_ids - sub_ids

    print(f"snapshot {FETCH_DATE}: sub-window retrievals (A+B+D) vs full-period retrieval (C)")
    print(f"  records in sub-window retrievals : {len(sub_ids):>7}")
    print(f"  records in full-period retrieval : {len(full_ids):>7}")
    print(f"  shared                           : {len(both):>7}")
    print(f"  only in sub-window               : {len(only_sub):>7}")
    print(f"  only in full-period              : {len(only_full):>7}")
    print()

    diff = [c for c in both if sub[c][1] != full[c][0]]
    print(f"  status differs between retrievals: {len(diff)} / {len(both)}")
    pairs = Counter((sub[c][0], sub[c][1], full[c][0]) for c in diff)
    for (grp, s_sub, s_full), n in pairs.most_common():
        print(f"    Group {grp}: {s_sub} -> {s_full}: {n}")
    for c in sorted(diff)[:a.show_ids]:
        print(f"      {c}  Group {sub[c][0]}  {sub[c][1]} -> {full[c][0]}  (published {sub[c][2][:19]})")
    if len(diff) > a.show_ids:
        print(f"      ... and {len(diff) - a.show_ids} more")
    print()

    if only_full:
        print(f"  only in full-period retrieval (late arrivals) - first {a.show_ids}:")
        st = Counter(full[c][0] for c in only_full)
        for s, n in st.most_common():
            print(f"    {s}: {n}")
        for c in sorted(only_full, key=lambda x: full[x][1])[:a.show_ids]:
            print(f"      {c}  {full[c][0]}  (published {full[c][1][:19]})")
        print()

    if only_sub:
        print(f"  only in sub-window retrievals - first {a.show_ids}:")
        for c in sorted(only_sub)[:a.show_ids]:
            print(f"      {c}  Group {sub[c][0]}  {sub[c][1]}  (published {sub[c][2][:19]})")
        print()


if __name__ == "__main__":
    main()
