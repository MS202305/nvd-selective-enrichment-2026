#!/usr/bin/env python3
''' NVD-assigned enrichment share by vulnStatus.

 For each status present in a group file, reports how many records carry
 at least one NVD-assigned CVSS base score, at least one NVD-assigned real
 CWE, and an NVD-generated CPE configuration. Used to check whether a
 status label (e.g. "Modified") is a valid proxy for "NVD-enriched".

 Provenance rules follow IVA-IVB_enrichment_and_composition_full.py:
 CVSS/CWE source == nvd@nist.gov, CPE present in "configurations",
 placeholder CWEs (NVD-CWE-noinfo, NVD-CWE-Other) not counted.'''

import json
import argparse
from collections import Counter, defaultdict

from config import FILE_GROUP_C

NVD = "nvd@nist.gov"
CWE_PLACEHOLDERS = {"NVD-CWE-noinfo", "NVD-CWE-Other"}


def has_nvd_cvss(cve):
    for arr in cve.get("metrics", {}).values():
        if not isinstance(arr, list):
            continue
        for e in arr:
            if not isinstance(e, dict) or e.get("source") != NVD:
                continue
            d = e.get("cvssData")
            if isinstance(d, dict) and isinstance(d.get("baseScore"), (int, float)):
                return True
    return False


def has_nvd_cwe(cve):
    for w in cve.get("weaknesses", []) or []:
        if not isinstance(w, dict) or w.get("source") != NVD:
            continue
        for d in w.get("description", []) or []:
            if isinstance(d, dict):
                val = d.get("value")
                if val and val not in CWE_PLACEHOLDERS:
                    return True
    return False


def has_nvd_cpe(wrapper, cve):
    # Same rule as IVA-IVB_enrichment_and_composition_full.nvd_cpe_entries:
    # at least one cpeMatch entry under configurations[].nodes[].
    for container in (wrapper, cve):
        if not isinstance(container, dict):
            continue
        for cfg in container.get("configurations", []) or []:
            if isinstance(cfg, dict):
                for node in cfg.get("nodes", []) or []:
                    if isinstance(node, dict):
                        m = node.get("cpeMatch", [])
                        if isinstance(m, list) and len(m) > 0:
                            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=FILE_GROUP_C)
    ap.add_argument("--status", default=None,
                    help="restrict to one vulnStatus; default: report all")
    a = ap.parse_args()

    with open(a.file, encoding="utf-8") as f:
        vulns = json.load(f)["vulnerabilities"]

    n = Counter()
    cvss = Counter()
    cwe = Counter()
    cpe = Counter()
    any_ = Counter()

    for v in vulns:
        cve = v.get("cve", {})
        st = cve.get("vulnStatus", "(missing)")
        if a.status and st != a.status:
            continue
        n[st] += 1
        c1 = has_nvd_cvss(cve)
        c2 = has_nvd_cwe(cve)
        c3 = has_nvd_cpe(v, cve)
        cvss[st] += c1
        cwe[st] += c2
        cpe[st] += c3
        any_[st] += (c1 or c2 or c3)

    pct = lambda x, t: f"{x/t*100:6.2f}%" if t else "   n/a"

    print(f"file: {a.file}")
    print(f"{'status':<20} {'n':>7} | {'NVD CVSS':>16} | {'NVD CWE':>16} | "
          f"{'NVD CPE':>16} | {'any NVD':>16}")
    for st in sorted(n, key=lambda s: -n[s]):
        t = n[st]
        print(f"{st:<20} {t:>7} | {cvss[st]:>7} {pct(cvss[st], t)} | "
              f"{cwe[st]:>7} {pct(cwe[st], t)} | "
              f"{cpe[st]:>7} {pct(cpe[st], t)} | "
              f"{any_[st]:>7} {pct(any_[st], t)}")


if __name__ == "__main__":
    main()
