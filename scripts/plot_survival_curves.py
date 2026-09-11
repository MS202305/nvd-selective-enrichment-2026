#!/usr/bin/env python3
'''Plots the empirical survival function (complementary CDF) of EPSS scores
 for each excluded group against the full analyzed reference set:
   Fig. 1.  Group A (backlog)      vs Group C
   Fig. 2.  Group B (post-policy)  vs Group C

 The survival function S(x) = P(EPSS >= x) is the fraction of a group's
 records whose EPSS score is at least x. Both axes are logarithmic. 
 The comparison uses the full reference set (the unadjusted, Stage-1 view); the age and
 KEV-controlled stages are reported in the results table (Table III).

 EPSS values are obtained from the FIRST-published EPSS snapshot, records
 with no EPSS match are dropped and their count is printed.'''

import csv
import json
import argparse
import numpy as np
import matplotlib.pyplot as plt

from config import (
    FETCH_DATE,
    FILE_EPSS,
    FILE_GROUP_A,
    FILE_GROUP_B,
    FILE_GROUP_C,
    STATUS_EXCLUDED,
    STATUS_REFERENCE,
)


def load_epss(path):
    epss = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or line.startswith("cve,"):
                continue
            parts = line.rstrip("\n").split(",")
            if len(parts) >= 2:
                try:
                    epss[parts[0]] = float(parts[1])
                except ValueError:
                    pass
    return epss


def group_scores(path, status, epss):
    with open(path, encoding="utf-8") as f:
        records = [v["cve"] for v in json.load(f)["vulnerabilities"]
                   if v.get("cve", {}).get("vulnStatus") == status]
    scores = [epss[c["id"]] for c in records if c.get("id") in epss]
    dropped = len(records) - len(scores)
    return np.array(sorted(scores)), dropped


def survival(scores):
    #For sorted scores, S(x) at each observed value is the fraction of
    #points >= that value. Return the x (scores) and y (survival) arrays.
    n = len(scores)
    #rank i (0-based) -> i points are strictly below, so n-i are >=
    y = (n - np.arange(n)) / n
    return scores, y


def plot(excluded, exc_label, exc_n, reference, ref_label, ref_n, out):
    xe, ye = survival(excluded)
    xr, yr = survival(reference)

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.step(xe, ye, where="post", color="#1f77b4",
            linewidth=1.8, label=f"{exc_label} (n = {exc_n:,})")
    ax.step(xr, yr, where="post", color="#ff7f0e", linewidth=1.8,
            linestyle="--", label=f"{ref_label} (n = {ref_n:,})")

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("EPSS score (log)")
    ax.set_ylabel(r"$P(\mathrm{EPSS} \geq x)$ (log)")
    ax.grid(True, which="both", linewidth=0.3, alpha=0.5)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(out, dpi=300)
    fig.savefig(out.replace(".png", ".pdf"))
    plt.close(fig)
    print(f"wrote {out} (and .pdf)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--group-a", default=FILE_GROUP_A)
    ap.add_argument("--group-b", default=FILE_GROUP_B)
    ap.add_argument("--group-c", default=FILE_GROUP_C)
    ap.add_argument("--epss", default=FILE_EPSS)
    ap.add_argument("--excluded-status", default=STATUS_EXCLUDED)
    ap.add_argument("--reference-status", default=STATUS_REFERENCE)
    ap.add_argument("--out-a", default=f"fig_survival_A_vs_C_{FETCH_DATE}.png")
    ap.add_argument("--out-b", default=f"fig_survival_B_vs_C_{FETCH_DATE}.png")
    a = ap.parse_args()

    epss = load_epss(a.epss)
    A, da = group_scores(a.group_a, a.excluded_status, epss)
    B, db = group_scores(a.group_b, a.excluded_status, epss)
    C, dc = group_scores(a.group_c, a.reference_status, epss)
    print(f"Group A: {len(A)} scores ({da} dropped)")
    print(f"Group B: {len(B)} scores ({db} dropped)")
    print(f"Group C: {len(C)} scores ({dc} dropped)")

    plot(A, "Group A (Deferred)", len(A), C, "Group C (Analyzed)", len(C), a.out_a)
    plot(B, "Group B (Deferred)", len(B), C, "Group C (Analyzed)", len(C), a.out_b)


if __name__ == "__main__":
    main()
