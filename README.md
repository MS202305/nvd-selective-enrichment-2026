# Reproduction package

Scripts and data snapshots for the paper "An Empirical Analysis of
Exploitability Signals in CVEs Excluded by NIST's Selective Enrichment
Policy". All snapshots are pinned to the UTC calendar day of June 29, 2026
(paper Section III.C).

## Layout

```
scripts/
  IVA-IVB_enrichment_and_composition_full.py
  IVC-IVD_ExploitabilityProfileOfExcludes.py
  IVE_group_d_status_breakdown.py
  plot_survival_curves.py
  verify_enrichment_and_composition.py
  wordpress_union_share.py
data/
  raw/
    nvd_group_A_2026-06-29.json.gz     backlog       (Deferred, filtered n = 29,062)
    nvd_group_B_2026-06-29.json.gz     post-policy   (Deferred, filtered n =  6,615)
    nvd_group_C_2026-06-29.json.gz     reference     (Analyzed, filtered n = 62,192)
    nvd_group_D_2026-06-29.json.gz     transition    (all statuses, n = 9,427)
  processed/
    source_registry.json               source id -> organization name (793 entries)
  snapshots/
    known_exploited_vulnerabilities.json   CISA KEV catalog (1,630 entries, commit 7fcbb766)
    epss_scores-2026-06-29.csv             FIRST EPSS daily file (plain CSV)
```

The four NVD group files are gzip-compressed. The EPSS file is a plain,
uncompressed CSV. Decompress the NVD files before running any script:

```
gzip -d data/raw/*.json.gz
```

Each script reads the paths above by default (relative to the `scripts/`
directory); every path can be overridden with command-line flags
(`--group-a`, `--group-c`, `--epss`, `--kev`, ...). Run any script with
`-h` to see its flags.

## Group definitions

Each NVD group file already contains only the records published inside the
group's date window (applied when the data was retrieved from the API,
paper Section III.A). The scripts then apply the vulnStatus filter below.

| Group | Publication window | vulnStatus | Raw | Filtered |
| --- | --- | --- | --- | --- |
| A (backlog)     | 2024-02-12 to 2026-02-28 | Deferred     | 97,103  | 29,062 |
| B (post-policy) | 2026-04-15 to 2026-06-29 | Deferred     | 17,105  |  6,615 |
| C (reference)   | 2024-02-12 to 2026-06-29 | Analyzed     | 123,639 | 62,192 |
| D (transition)  | 2026-03-01 to 2026-04-14 | all statuses | 9,427   |  9,427 |

For Group D the KEV check uses the Deferred subset (2,330 records).

## Requirements

Python 3.9 or newer. Four scripts use only the standard library.
`IVC-IVD_ExploitabilityProfileOfExcludes.py` requires `scipy`, and
`plot_survival_curves.py` requires `numpy` and `matplotlib`:

```
pip install scipy numpy matplotlib
```

## Which script reproduces which part of the paper

**`IVA-IVB_enrichment_and_composition_full.py`** — Section IV.A and
Section IV.B (Table II). Reports CPE, CWE, and CVSS completeness at both
record and entry level for Groups A and B, the KEV intersection for
Groups A, B, and D, and the per-source composition behind Table II.

**`IVC-IVD_ExploitabilityProfileOfExcludes.py`** — Sections IV.C and IV.D
(Table III). Reports EPSS coverage (including the 89 unmatched Group B
records), descriptive statistics, the threshold counts (EPSS >= 0.05,
0.5, 0.7 and the single highest score per group), the top-10 EPSS lists,
and the three-stage Mann-Whitney control chains for RQ1 and RQ2.

**`IVE_group_d_status_breakdown.py`** — Section IV.E. Breaks the
transition window (Group D) down by `vulnStatus` into Analyzed, Deferred,
and other.

**`plot_survival_curves.py`** — Fig. 2 (Group A vs C) and Fig. 3
(Group B vs C): the empirical EPSS survival functions on a log-log scale.
Writes PNG and PDF.

**`wordpress_union_share.py`** — the Patchstack/Wordfence union figures
used in Sections IV.B and V.B. Computes them by inclusion-exclusion over
CVE id sets and confirms that the two companies' intersection is empty in
both groups.

**`verify_enrichment_and_composition.py`** — an earlier, record-level
consolidation of the same IV.A / IV.B checks. Kept as an independent
cross-check of `IVA-IVB_enrichment_and_composition_full.py`.

## Data notes

**NVD group snapshots.** Retrieved from the NVD API 2.0 with the
`pubStartDate` / `pubEndDate` parameters in 10-day windows (paper
Section III.A). These are the exact files behind the paper's numbers;
re-crawling the API today would not reproduce them, because records change
status over time. Group filtering (by `vulnStatus` and publication window)
happens inside the scripts, so each `.json` holds the raw per-group
retrieval and the scripts report the filtered counts shown above.

**source_registry.json.** A lookup table that maps each `source`
identifier (an email or UUID appearing in the NVD records) to the
contributing organization's name, built from NVD's official Source API
(paper reference [28]). It is a derived input, not an analysis output: the
scripts read it to label sources and never modify it. Because the Source
API is deterministic, anyone querying it obtains the same mapping, so the
file is provided directly and no generation script is needed.

**CISA KEV.** Catalog version pinned through the commit history of the
official GitHub repository (commit 7fcbb766).

**FIRST EPSS.** The daily CSV published for June 29, 2026. Its first line
is a metadata comment (`model_version`, `score_date`); the scripts skip it
and the header row.

## Method notes

- "NVD-assigned" means the entry's `source` is `nvd@nist.gov` (for CVSS
  and CWE), or, for CPE, that it appears in the NVD-generated `configurations`
  field. CISA-ADP is treated as a non-NVD source throughout (paper
  Section III.E).
- CWE placeholder values (`NVD-CWE-noinfo`, `NVD-CWE-Other`) are not
  counted as real classifications.
- In the source-composition tables a record may carry entries from several
  organizations, so a record can be counted under more than one source and
  the column percentages need not sum to 100%.
