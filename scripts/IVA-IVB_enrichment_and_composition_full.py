#!/usr/bin/env python3
''' Reproduces every figure in Sections IV.A.Enrichment Completeness and KEV
 Intersection and IV.B. Source Provider Composition of the paper
 for the excluded groups (A = backlog, B = post-policy; Deferred Records)
 and the transition Group D. 

 For each of the three enrichment fields (CPE, CWE, CVSS) the script
 reports provenance at :

   record-level : how many records carry the field (a record counts once,
    regardless of how many entries it holds). 

   entry-level  : how many individual entries exist (for instance a record with three
    CVSS metrics contributes three). 

 NVD-assigned means the entry's source is nvd@nist.gov (for CVSS and CWE)
 for CPE, that it sits in the NVD-generated "configurations" field.
 NOTETHAT: CISA-ADP is taken as a non-NVD source. CWE placeholder values
 (NVD-CWE-noinfo, NVD-CWE-Other) are not counted as real classifications (These are placeholders).

 In the source-composition table (Table II) a record may carry entries from several
 organizations, so a record can be counted under more than one source and
 the column percentages need not sum to 100%.'''

import json
import argparse
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

def resolve(src, registry):
    if src is None:
        return "(unknown source)"
    return registry.get(src, src)

def load_group(path, status):
    data = load_json(path)
    out = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        if status is None or cve.get("vulnStatus") == status:
            out.append((v, cve))
    return out

def load_kev(path):
    data = load_json(path)
    return {v.get("cveID") for v in data.get("vulnerabilities", [])
            if isinstance(v, dict) and v.get("cveID")}


#CPE: NVD-generated (configurations) versus CNA-supplied (affected)
def nvd_cpe_entries(wrapper, cve):
    #count NVD-generated CPE match strings under configurations
    total = 0
    for container in (wrapper, cve):
        if not isinstance(container, dict):
            continue
        for cfg in container.get("configurations", []) or []:
            if isinstance(cfg, dict):
                for node in cfg.get("nodes", []) or []:
                    if isinstance(node, dict):
                        m = node.get("cpeMatch", [])
                        if isinstance(m, list):
                            total += len(m)
    return total

def cna_cpe(cve, registry):
    #(entry_count, {org -> entry_count}) for CNA-supplied CPEs in 'affected'
    total = 0
    by_org = Counter()
    for block in cve.get("affected", []) or []:
        if not isinstance(block, dict):
            continue
        n = 0
        for ad in block.get("affectedData", []) or []:
            if isinstance(ad, dict) and isinstance(ad.get("cpes"), list):
                n += len(ad["cpes"])
        if isinstance(block.get("cpes"), list):
            n += len(block["cpes"])
        if n:
            total += n
            by_org[resolve(block.get("source"), registry)] += n
    return total, by_org


#CWE: real (non-placeholder) classifications, NVD vs non-NVD
def cwe_entries(cve, registry):
    # Returns per-record flags and entry counts:
    # nvd_entries, nonnvd_entries, and the set of non-NVD orgs (record-level)
    nvd_entries = 0
    nonnvd_entries = 0
    orgs = set()
    for w in cve.get("weaknesses", []) or []:
        if not isinstance(w, dict):
            continue
        src = w.get("source")
        for d in w.get("description", []) or []:
            if isinstance(d, dict):
                val = d.get("value")
                if val and val not in CWE_PLACEHOLDERS:
                    if src == NVD:
                        nvd_entries += 1
                    else:
                        nonnvd_entries += 1
                        orgs.add(resolve(src, registry))
    return nvd_entries, nonnvd_entries, orgs


# CVSS: base scores, NVD vs non-NVD
def cvss_entries(cve, registry):
    #Returns nvd_entries, nonnvd_entries, and the set of non-NVD orgs
    nvd_entries = 0
    nonnvd_entries = 0
    orgs = set()
    for arr in cve.get("metrics", {}).values():
        if not isinstance(arr, list):
            continue
        for e in arr:
            if not isinstance(e, dict):
                continue
            d = e.get("cvssData")
            if not (isinstance(d, dict) and isinstance(d.get("baseScore"), (int, float))):
                continue
            if e.get("source") == NVD:
                nvd_entries += 1
            else:
                nonnvd_entries += 1
                orgs.add(resolve(e.get("source"), registry))
    return nvd_entries, nonnvd_entries, orgs


# Section IV.A: completeness, record and entry-level
def completeness(name, records, registry):
    n = len(records)
    rp = lambda x: round(x / n * 100, 2) if n else 0.0

    #record-level counters
    rec_nvd_cpe = rec_cna_cpe = 0
    rec_cwe_real = rec_cwe_nvd = 0
    rec_cvss_nonnvd = rec_cvss_nvd = 0
    #entry-level counters
    ent_nvd_cpe = ent_cna_cpe = 0
    ent_cwe_nvd = ent_cwe_nonnvd = 0
    ent_cvss_nvd = ent_cvss_nonnvd = 0

    for wrapper, cve in records:
        ncpe = nvd_cpe_entries(wrapper, cve)
        ccpe, _ = cna_cpe(cve, registry)
        ent_nvd_cpe += ncpe
        ent_cna_cpe += ccpe
        if ncpe:
            rec_nvd_cpe += 1
        if ccpe:
            rec_cna_cpe += 1

        cwe_nvd, cwe_non, _ = cwe_entries(cve, registry)
        ent_cwe_nvd += cwe_nvd
        ent_cwe_nonnvd += cwe_non
        if cwe_nvd or cwe_non:
            rec_cwe_real += 1
        if cwe_nvd:
            rec_cwe_nvd += 1

        cv_nvd, cv_non, _ = cvss_entries(cve, registry)
        ent_cvss_nvd += cv_nvd
        ent_cvss_nonnvd += cv_non
        if cv_non:
            rec_cvss_nonnvd += 1
        if cv_nvd:
            rec_cvss_nvd += 1

    print(f"[{name}] completeness  (n = {n})")
    print(f"  CPE  record-level : NVD {rec_nvd_cpe} ({rp(rec_nvd_cpe)}%), "
          f"CNA {rec_cna_cpe} ({rp(rec_cna_cpe)}%)")
    print(f"       entry-level  : NVD {ent_nvd_cpe}, CNA {ent_cna_cpe}")
    print(f"  CWE  record-level : real {rec_cwe_real} ({rp(rec_cwe_real)}%), "
          f"NVD-assigned {rec_cwe_nvd} ({rp(rec_cwe_nvd)}%)")
    print(f"       entry-level  : NVD {ent_cwe_nvd}, non-NVD {ent_cwe_nonnvd}")
    print(f"  CVSS record-level : non-NVD {rec_cvss_nonnvd} ({rp(rec_cvss_nonnvd)}%), "
          f"NVD-assigned {rec_cvss_nvd} ({rp(rec_cvss_nvd)}%)")
    print(f"       entry-level  : NVD {ent_cvss_nvd}, non-NVD {ent_cvss_nonnvd}")
    print()


#Section IV.A: KEV intersection
def kev_intersection(name, records, kev):
    ids = {cve.get("id") for _, cve in records}
    hit = ids & kev
    print(f"[{name}] KEV intersection: {len(hit)}/{len(ids)}")
    if hit:
        print(f"  KEV ids (sample): {sorted(hit)[:10]}")

#Section IV.B: source composition (Table II), record-level shares
def composition(name, records, registry, top=6):
    n = len(records)
    rp = lambda x: round(x / n * 100, 2) if n else 0.0

    cvss_by_src = Counter()
    cwe_by_src = Counter()
    for _, cve in records:
        _, _, cv_orgs = cvss_entries(cve, registry)
        _, _, cw_orgs = cwe_entries(cve, registry)
        for o in cv_orgs:
            cvss_by_src[o] += 1
        for o in cw_orgs:
            cwe_by_src[o] += 1

    print(f"[{name}] source composition  (n = {n})")
    print(f"  {'source':<28} | {'CVSS rec':>8} {'CVSS %':>7} | "
          f"{'CWE rec':>8} {'CWE %':>7}")
    for org, c in cvss_by_src.most_common(top):
        w = cwe_by_src.get(org, 0)
        print(f"  {org:<28} | {c:>8} {rp(c):>6}% | {w:>8} {rp(w):>6}%")

    pw = ["Patchstack", "Wordfence"]
    cvss_combo = sum(cvss_by_src.get(o, 0) for o in pw)
    cwe_combo = sum(cwe_by_src.get(o, 0) for o in pw)
    print(f"  {'Patchstack + Wordfence':<28} | "
          f"{'':>8} {rp(cvss_combo):>6}% | {'':>8} {rp(cwe_combo):>6}%")
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Reproduce Sections IV.A and IV.B at record- and "
                    "entry-level for the excluded CVE groups.")
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
    D = load_group(args.group_d, args.status)

    print("=" * 62)
    print("IV.A  ENRICHMENT COMPLETENESS  (record and entry-level)")
    print("=" * 62)
    completeness("Group A", A, registry)
    completeness("Group B", B, registry)

    print("=" * 62)
    print("IV.A  KEV INTERSECTION")
    print("=" * 62)
    kev_intersection("Group A", A, kev)
    kev_intersection("Group B", B, kev)
    kev_intersection("Group D", D, kev)
    print()

    print("=" * 62)
    print("IV.B  SOURCE PROVIDER COMPOSITION  (Table II)")
    print("=" * 62)
    composition("Group A", A, registry)
    composition("Group B", B, registry)


if __name__ == "__main__":
    main()
