#!/usr/bin/env python3
''' Reproduces the numbers in Sections IV.A. Enrichment Completeness and KEV
 Intersection and IV.B. Source Provider Composition, Table II of the paper,
 for the two excluded groups (A = backlog, B = post-policy; both Deferred)
 and the transition Group D (KEV check only).

 Every "source" identifier is resolved to an organization name through a
 registry file. CISA-ADP is treated as a non-NVD source.

 A CVE may carry data from several sources, so in the coverage table (Table II)  the
 same record can be counted under more than one source and column
 percentages need not sum to 100%.'''

import json
import argparse
import statistics
from collections import Counter

from config import (
    FILE_GROUP_A,
    FILE_GROUP_B,
    FILE_GROUP_D,
    FILE_KEV,
    FILE_REGISTRY,
    STATUS_EXCLUDED,
)

NVD = "nvd@nist.gov"
CWE_PLACEHOLDERS = {"NVD-CWE-noinfo", "NVD-CWE-Other"}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_registry(path):
    if not path:
        return {}
    try:
        reg = load_json(path)
        return reg if isinstance(reg, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def resolve(source_id, registry):
    if source_id is None:
        return "(unknown source)"
    return registry.get(source_id, source_id)


def load_group(path, status):
    #Deferred records for A/B, for D we pass status=None to take all records.
    data = load_json(path)
    out = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        if status is None or cve.get("vulnStatus") == status:
            out.append((v, cve))   # keep wrapper (for configurations) and cve
    return out


def load_kev(path):
    data = load_json(path)
    return {v.get("cveID") for v in data.get("vulnerabilities", [])
            if isinstance(v, dict) and v.get("cveID")}


#Field extractors
def configurations(wrapper, cve):
    for c in (wrapper, cve):
        if isinstance(c, dict) and isinstance(c.get("configurations"), list):
            return c["configurations"]
    return []


def has_nvd_cpe(wrapper, cve):
    # Same rule as IVA-IVB_enrichment_and_composition_full.nvd_cpe_entries:
    # at least one cpeMatch entry under configurations[].nodes[].
    for cfg in configurations(wrapper, cve):
        if isinstance(cfg, dict):
            for node in cfg.get("nodes", []) or []:
                if isinstance(node, dict):
                    m = node.get("cpeMatch", [])
                    if isinstance(m, list) and len(m) > 0:
                        return True
    return False


def cna_cpe_sources(cve, registry):
    #organizations that supply CPEs via the 'affected' field, and whether this record has any CNA CPE at all
    orgs = set()
    for block in cve.get("affected", []) or []:
        if not isinstance(block, dict):
            continue
        n = 0
        for ad in block.get("affectedData", []) or []:
            if isinstance(ad, dict) and isinstance(ad.get("cpes"), list):
                n += len(ad["cpes"])
        if isinstance(block.get("cpes"), list):
            n += len(block["cpes"])
        if n > 0:
            orgs.add(resolve(block.get("source"), registry))
    return orgs


def cwe_sources(cve, registry):
    #organizations that assign a real (non-placeholder) CWE
    orgs = set()
    has_nvd = False
    has_real = False
    for w in cve.get("weaknesses", []) or []:
        if not isinstance(w, dict):
            continue
        src = w.get("source")
        real_here = False
        for d in w.get("description", []) or []:
            if isinstance(d, dict):
                val = d.get("value")
                if val and val not in CWE_PLACEHOLDERS:
                    real_here = True
                    break
        if real_here:
            has_real = True
            orgs.add(resolve(src, registry))
            if src == NVD:
                has_nvd = True
    return orgs, has_nvd, has_real


def cvss_score_sources(cve, registry):
    #organizations that assign a CVSS base score, 
    #returns (set_of_orgs, has_nvd_score, has_nonnvd_score)
    orgs = set()
    has_nvd = False
    has_nonnvd = False
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
            if src == NVD:
                has_nvd = True
            elif src:
                has_nonnvd = True
                orgs.add(resolve(src, registry))
    return orgs, has_nvd, has_nonnvd


#Section IV.A: completeness
def section_a_completeness(name, records, registry):
    total = len(records)
    pct = lambda x: round(x / total * 100, 4) if total else 0.0

    nvd_cpe = cna_cpe = 0
    cwe_cov = cwe_nvd = 0
    cvss_cov = cvss_nvd = 0

    for wrapper, cve in records:
        if has_nvd_cpe(wrapper, cve):
            nvd_cpe += 1
        if cna_cpe_sources(cve, registry):
            cna_cpe += 1
        _, has_nvd_c, has_real_c = cwe_sources(cve, registry)
        if has_real_c:
            cwe_cov += 1
        if has_nvd_c:
            cwe_nvd += 1
        _, has_nvd_v, has_nonnvd_v = cvss_score_sources(cve, registry)
        if has_nonnvd_v:
            cvss_cov += 1
        if has_nvd_v:
            cvss_nvd += 1

    print(f"[{name}] completeness  (n = {total})")
    print(f"  CPE  NVD-generated (configurations) : {nvd_cpe} ({pct(nvd_cpe)}%)")
    print(f"  CPE  CNA-supplied  (affected)       : {cna_cpe} ({pct(cna_cpe)}%)")
    print(f"  CWE  coverage (real)                : {cwe_cov} ({pct(cwe_cov)}%)")
    print(f"  CWE  NVD-assigned                   : {cwe_nvd} ({pct(cwe_nvd)}%)")
    print(f"  CVSS non-NVD base score             : {cvss_cov} ({pct(cvss_cov)}%)")
    print(f"  CVSS NVD-assigned base score        : {cvss_nvd} ({pct(cvss_nvd)}%)")
    print()


#Section IV.A: KEV intersection
def section_a_kev(name, records, kev):
    ids = {cve.get("id") for _, cve in records}
    hit = ids & kev
    total = len(ids)
    print(f"[{name}] KEV intersection: {len(hit)}/{total} "
          f"({round(len(hit)/total*100,4) if total else 0.0}%)")
    if hit:
        print(f"  KEV-listed ids (sample): {sorted(hit)[:10]}")


# Section IV.B: source composition (Table II)
def section_b_composition(name, records, registry, top=6):
    total = len(records)
    pct = lambda x: round(x / total * 100, 2) if total else 0.0

    cvss_by_src = Counter()
    cwe_by_src = Counter()
    for _, cve in records:
        for org in cvss_score_sources(cve, registry)[0]:
            cvss_by_src[org] += 1
        for org in cwe_sources(cve, registry)[0]:
            cwe_by_src[org] += 1

    print(f"[{name}] source composition  (n = {total})")
    print(f"  Top {top} CVSS-score sources (source | records | %):")
    for org, cnt in cvss_by_src.most_common(top):
        print(f"    {org:<28} | {cnt:>6} | {pct(cnt):>6}%  "
              f"(CWE {pct(cwe_by_src.get(org,0))}%)")

    pw = ["Patchstack", "Wordfence"]
    cvss_combo = pct(sum(cvss_by_src.get(o, 0) for o in pw))
    cwe_combo = pct(sum(cwe_by_src.get(o, 0) for o in pw))
    print(f"  Patchstack + Wordfence combined: "
          f"CVSS {cvss_combo}%   CWE {cwe_combo}%")
    print(f"  (a record may be counted under several sources; column "
          f"percentages need not sum to 100%)")
    print()
    return cvss_by_src, cwe_by_src

def main():
    ap = argparse.ArgumentParser(
        description="Reproduce Section A (completeness + KEV) and Section B "
                    "(source composition, Table II) for the excluded groups.")
    ap.add_argument("--group-a", default=FILE_GROUP_A)
    ap.add_argument("--group-b", default=FILE_GROUP_B)
    ap.add_argument("--group-d", default=FILE_GROUP_D)
    ap.add_argument("--registry", default=FILE_REGISTRY)
    ap.add_argument("--kev", default=FILE_KEV)
    ap.add_argument("--status", default=STATUS_EXCLUDED)
    args = ap.parse_args()

    registry = load_registry(args.registry)
    kev = load_kev(args.kev)
    print(f"registry: {len(registry)} sources;  KEV: {len(kev)} CVEs\n")

    A = load_group(args.group_a, args.status)
    B = load_group(args.group_b, args.status)
    D = load_group(args.group_d, args.status)   # Deferred subset of D for KEV

    print("=" * 60)
    print("SECTION A - Enrichment Completeness")
    print("=" * 60)
    section_a_completeness("Group A", A, registry)
    section_a_completeness("Group B", B, registry)

    print("=" * 60)
    print("SECTION A - KEV Intersection (deferred records)")
    print("=" * 60)
    section_a_kev("Group A", A, kev)
    section_a_kev("Group B", B, kev)
    section_a_kev("Group D", D, kev)
    print()

    print("=" * 60)
    print("SECTION B - Source Provider Composition (Table II)")
    print("=" * 60)
    section_b_composition("Group A", A, registry)
    section_b_composition("Group B", B, registry)


if __name__ == "__main__":
    main()
