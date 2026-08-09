#!/usr/bin/env python3
'''Union share of Patchstack and Wordfence in the excluded groups, computed
 by inclusion-exclusion over CVE id sets.

 For CVSS: collect the set P of CVE ids carrying at least one Patchstack
 base score and the set W of ids carrying at least one Wordfence base
 score, then |P u W| = |P| + |W| - |P n W|. The same is done for CWE
 (for real, non-placeholder classifications). |P| and |W| should match the
 per-source record counts in Table II, which makes the computation easy
 to cross-check. '''

import json
import argparse

NVD = "nvd@nist.gov"
CWE_PLACEHOLDERS = {"NVD-CWE-noinfo", "NVD-CWE-Other"}


def load_registry(path):
    with open(path, encoding="utf-8") as f:
        reg = json.load(f)
    return reg if isinstance(reg, dict) else {}


def load_group(path, status):
    with open(path, encoding="utf-8") as f:
        return [v["cve"] for v in json.load(f)["vulnerabilities"]
                if v.get("cve", {}).get("vulnStatus") == status]


def cvss_id_set(records, registry, org):
    #CVE ids with at least one base score assigned by the given organization
    ids = set()
    for cve in records:
        for arr in cve.get("metrics", {}).values():
            if not isinstance(arr, list):
                continue
            for e in arr:
                if not isinstance(e, dict):
                    continue
                d = e.get("cvssData")
                if not (isinstance(d, dict) and isinstance(d.get("baseScore"), (int, float))):
                    continue
                src = e.get("source")
                if src and registry.get(src, src) == org:
                    ids.add(cve.get("id"))
    return ids


def cwe_id_set(records, registry, org):
    #CVE ids with at least one real CWE assigned by the given organization
    ids = set()
    for cve in records:
        for w in cve.get("weaknesses", []) or []:
            if not isinstance(w, dict):
                continue
            src = w.get("source")
            if not src or registry.get(src, src) != org:
                continue
            for d in w.get("description", []) or []:
                if isinstance(d, dict):
                    val = d.get("value")
                    if val and val not in CWE_PLACEHOLDERS:
                        ids.add(cve.get("id"))
                        break
    return ids


def report(field, p_ids, w_ids, n):
    union = p_ids | w_ids
    inter = p_ids & w_ids
    pct = lambda x: round(x / n * 100, 2) if n else 0.0
    print(f"  {field}")
    print(f"    Patchstack |P|          : {len(p_ids)} ({pct(len(p_ids))}%)")
    print(f"    Wordfence  |W|          : {len(w_ids)} ({pct(len(w_ids))}%)")
    print(f"    intersection |P n W|    : {len(inter)}")
    print(f"    union |P u W| = |P|+|W|-|P n W| : "
          f"{len(p_ids)} + {len(w_ids)} - {len(inter)} = {len(union)} ({pct(len(union))}%)")


def run(name, records, registry):
    n = len(records)
    print(f"{name}  (n = {n})")
    report("CVSS (base scores)",
           cvss_id_set(records, registry, "Patchstack"),
           cvss_id_set(records, registry, "Wordfence"), n)
    report("CWE (real classifications)",
           cwe_id_set(records, registry, "Patchstack"),
           cwe_id_set(records, registry, "Wordfence"), n)
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--group-a", default="../data/raw/nvd_group_A_2026-06-29.json")
    ap.add_argument("--group-b", default="../data/raw/nvd_group_B_2026-06-29.json")
    ap.add_argument("--registry", default="../data/processed/source_registry.json")
    ap.add_argument("--status", default="Deferred")
    a = ap.parse_args()

    registry = load_registry(a.registry)
    run("Group A", load_group(a.group_a, a.status), registry)
    run("Group B", load_group(a.group_b, a.status), registry)


if __name__ == "__main__":
    main()
