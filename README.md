# NVD Selective Enrichment — Reproducibility Package

Scripts, configuration, raw data snapshots and analysis outputs for the paper
*An Empirical Analysis of Exploitability Signals in CVEs Excluded by NIST's
Selective Enrichment Policy* (SINCONF 2026, Paper ID 89).

Two UTC-aligned snapshots are analysed: **2026-06-29** (primary) and
**2026-09-01** (longitudinal replication, 64 days later).

## Repository layout

```
scripts/
  config_2026-06-29.py                 snapshot configuration (June)
  config_2026-09-01.py                 snapshot configuration (September)
  run_all.bat                          one-command reproduction (Windows)
  IVA-IVB_enrichment_and_composition_full.py
  IVC-IVD_ExploitabilityProfileOfExcludes.py
  IVE_group_d_status_breakdown.py
  provenance_by_status.py
  verify_enrichment_and_composition.py
  wordpress_union_share.py
  cross_retrieval_check.py
  status_transitions.py
  plot_survival_curves.py
data/
  raw/           NVD API 2.0 responses, one file per group and snapshot  (see "Data" below)
  snapshots/     FIRST EPSS daily CSV and CISA KEV catalog, one per snapshot
  processed/     source_registry.json  (NVD Source API: identifier -> organisation name)
out_2026-06-29/  analysis outputs for the June snapshot   (12 files)
out_2026-09-01/  analysis outputs for the September snapshot (15 files)
```

## Data

### NVD raw snapshots (`data/raw/`)

Eight files, one per group and snapshot, retrieved from the NVD API 2.0
(`https://services.nvd.nist.gov/rest/json/cves/2.0`) using `pubStartDate` /
`pubEndDate` in 10-day windows. **They are distributed gzip-compressed.**
The scripts read plain JSON, so decompress before running:

```
cd data/raw
gunzip *.json.gz            # Linux / macOS / Git Bash
```

or on Windows with Python:

```
python -c "import gzip,shutil,glob; [shutil.copyfileobj(gzip.open(f,'rb'),open(f[:-3],'wb')) for f in glob.glob('*.json.gz')]"
```

After decompression the directory must contain:

```
nvd_group_A_2026-06-29.json   nvd_group_A_2026-09-01.json
nvd_group_B_2026-06-29.json   nvd_group_B_2026-09-01.json
nvd_group_C_2026-06-29.json   nvd_group_C_2026-09-01.json
nvd_group_D_2026-06-29.json   nvd_group_D_2026-09-01.json
```

| File | Records (all statuses) |
|---|---|
| nvd_group_A_2026-06-29.json | 97,103 |
| nvd_group_B_2026-06-29.json | 17,105 |
| nvd_group_C_2026-06-29.json | 123,639 |
| nvd_group_D_2026-06-29.json | 9,427 |
| nvd_group_A_2026-09-01.json | 97,103 |
| nvd_group_B_2026-09-01.json | 40,386 |
| nvd_group_C_2026-09-01.json | 146,916 |
| nvd_group_D_2026-09-01.json | 9,427 |

### EPSS and KEV (`data/snapshots/`)

| File | Source | Pinned to |
|---|---|---|
| epss_scores-2026-06-29.csv | FIRST daily CSV | score_date 2026-06-29T12:00:29Z, 343,948 CVEs |
| epss_scores-2026-09-01.csv | FIRST daily CSV | score_date 2026-09-01T12:03:04Z, 366,848 CVEs |
| known_exploited_vulnerabilities_2026-06-29.json | cisagov/kev-data | commit 7fcbb766, 1,630 entries |
| known_exploited_vulnerabilities_2026-09-01.json | cisagov/kev-data | commit 9d5557b3 (2026-08-31), 1,687 entries |

### Source registry (`data/processed/source_registry.json`)

Mapping from NVD source identifiers (email / UUID) to organisation names,
retrieved from the NVD Source API (`https://services.nvd.nist.gov/rest/json/source/2.0`).
793 sources.

## Reproduction

Requirements: Python 3.10+, `scipy`, `numpy`, `matplotlib`.

All scripts import their file paths from `scripts/config.py`, which is a copy
of the snapshot-specific `config_<date>.py`. Because the two config files have
identical size and near-identical timestamps, Python's bytecode cache can miss
the change when switching snapshots. **Always clear `__pycache__` and disable
bytecode writing before each run**; the commands below do this.

### Windows (one command per snapshot)

```
cd scripts
run_all.bat 2026-06-29
run_all.bat 2026-09-01
```

`run_all.bat` copies the matching config to `config.py`, removes
`__pycache__`, sets `PYTHONDONTWRITEBYTECODE=1`, runs every script, and writes
outputs to `..\out_<date>\`.

### Linux / macOS

```
cd scripts
export PYTHONDONTWRITEBYTECODE=1
export MPLBACKEND=Agg

# --- June snapshot ---
rm -rf __pycache__ && cp config_2026-06-29.py config.py
mkdir -p ../out_2026-06-29
python3 IVA-IVB_enrichment_and_composition_full.py            > ../out_2026-06-29/IVA-IVB_enrichment_and_composition_full.txt
python3 provenance_by_status.py                               > ../out_2026-06-29/provenance_by_status.txt
python3 provenance_by_status.py --status Modified             > ../out_2026-06-29/provenance_modified.txt
python3 IVC-IVD_ExploitabilityProfileOfExcludes.py --bootstrap 1000 --top 15 --top-detail                        > ../out_2026-06-29/rq_A.txt
python3 IVC-IVD_ExploitabilityProfileOfExcludes.py --bootstrap 1000 --reference-status Analyzed,Modified         > ../out_2026-06-29/rq_AM.txt
python3 IVC-IVD_ExploitabilityProfileOfExcludes.py --bootstrap 1000 --exclude-sources Patchstack,Wordfence       > ../out_2026-06-29/rq_noWP.txt
python3 IVE_group_d_status_breakdown.py                       > ../out_2026-06-29/IVE_group_d_status_breakdown.txt
python3 wordpress_union_share.py                              > ../out_2026-06-29/wordpress_union_share.txt
python3 verify_enrichment_and_composition.py                  > ../out_2026-06-29/verify_enrichment_and_composition.txt
python3 cross_retrieval_check.py                              > ../out_2026-06-29/cross_retrieval_check.txt
python3 plot_survival_curves.py                               > ../out_2026-06-29/plot_survival_curves.txt

# --- September snapshot ---
rm -rf __pycache__ && cp config_2026-09-01.py config.py
mkdir -p ../out_2026-09-01
# (same eleven commands as above, writing to ../out_2026-09-01/)
# plus the June-to-September transition matrices:
python3 status_transitions.py --group A --show-ids 20                     > ../out_2026-09-01/transitions_A.txt
python3 status_transitions.py --group C --pub-end 2026-02-28 --show-ids 5 > ../out_2026-09-01/transitions_C.txt
python3 status_transitions.py --group D --show-ids 20                     > ../out_2026-09-01/transitions_D.txt
```

`status_transitions.py` compares the active snapshot against 2026-06-29 and is
therefore run only for the September config.

### Expected result

The `out_2026-06-29/` and `out_2026-09-01/` directories in this repository
were produced by exactly these commands. Re-running should reproduce every
number; the bootstrap uses a fixed seed (20260629), so confidence intervals
are deterministic. Each directory contains `_manifest.txt` with the config
that was active during the run.

## Script → paper section map

| Script | Output file | Paper |
|---|---|---|
| IVA-IVB_enrichment_and_composition_full.py | IVA-IVB_….txt | IV.A, IV.B, Table II, V.B |
| provenance_by_status.py | provenance_by_status.txt | V.B, V.C (Group C provenance) |
| provenance_by_status.py --status Modified | provenance_modified.txt | IV.E (Modified CPE = 100%) |
| IVC-IVD_… (default) | rq_A.txt | IV.C, IV.D, Table III, Table IV row 1, Table V |
| IVC-IVD_… --reference-status Analyzed,Modified | rq_AM.txt | Table IV row 2 |
| IVC-IVD_… --exclude-sources Patchstack,Wordfence | rq_noWP.txt | Table IV row 3, IV.E |
| IVE_group_d_status_breakdown.py | IVE_group_d_….txt | III.B (Group D) |
| wordpress_union_share.py | wordpress_union_share.txt | IV.B, IV.E, V.B, V.C (WordPress share) |
| verify_enrichment_and_composition.py | verify_….txt | independent re-computation of IV.A / IV.B |
| cross_retrieval_check.py | cross_retrieval_check.txt | III.C, IV.E |
| status_transitions.py | transitions_{A,C,D}.txt | IV.E, V.A (June → September transitions) |
| plot_survival_curves.py | fig_survival_*.png | Fig. 2, Fig. 3 |

## Provenance rules

- **NVD-assigned CVSS / CWE**: entry `source == "nvd@nist.gov"`. All other
  sources, including CISA-ADP, are non-NVD.
- **NVD-generated CPE**: at least one `cpeMatch` entry under
  `configurations[].nodes[]`.
- **CNA-supplied CPE**: `cpes` list under `affected[]` or `affected[].affectedData[]`.
- **CWE placeholders** `NVD-CWE-noinfo` and `NVD-CWE-Other` are not counted.
- Each organisation is counted once per record, regardless of entry count.
- Group membership uses the `published` field only; `lastModified` is never used
  (the 2026-06-17 SSVC deployment rewrote it for ~95% of records).

## Notes

- Group B's EPSS-matched sample (June: 6,526 of 6,615) is smaller than its
  population because 89 records were published after the EPSS file's
  generation time. The September window closes one day before collection to
  avoid this; the residual is 4 of 13,752.
- `status_transitions.py` compares the current `config.FETCH_DATE` snapshot
  against 2026-06-29 and is therefore meaningful only for the September config.
