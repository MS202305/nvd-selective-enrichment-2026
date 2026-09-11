@echo off
REM ===================================================================
REM  run_all.bat  <YYYY-MM-DD>
REM
REM  Activates the config for the given snapshot date and runs every
REM  script that produces a number in the paper. Outputs:
REM      ..\out_<date>\<name>.txt
REM
REM  USAGE (from the scripts\ directory):
REM      run_all.bat 2026-06-29
REM      run_all.bat 2026-09-01
REM
REM  Before every script call, __pycache__ is removed and
REM  PYTHONDONTWRITEBYTECODE=1 is set, so a config.py swap is never
REM  masked by stale bytecode.
REM
REM  Coverage (paper section -> output file):
REM    IV.A, IV.B, Table II, V.B (excluded)  -> IVA-IVB_enrichment_and_composition_full.txt
REM    V.B, V.C (Group C, all statuses)       -> provenance_by_status.txt
REM    IV.E (Modified CPE=100%)              -> provenance_modified.txt
REM    IV.C, IV.D, Table III, Table IV (A)   -> rq_A.txt
REM    IV.E, Table IV (A+M)                  -> rq_AM.txt
REM    IV.E, Table IV (non-WP)               -> rq_noWP.txt
REM    IV.E Group D                          -> IVE_group_d_status_breakdown.txt
REM    IV.E WordPress share                  -> wordpress_union_share.txt
REM    (verification: IV.A/IV.B, independent code path)     -> verify_enrichment_and_composition.txt
REM    III.C / IV.E cross-retrieval          -> cross_retrieval_check.txt
REM    IV.E per-CVE transitions (Sept only) -> transitions_A.txt, transitions_C.txt, transitions_D.txt
REM    Fig. 2, Fig. 3                        -> plot_survival_curves.txt (+PNG)
REM ===================================================================

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo ERROR: no snapshot date given.
    echo Usage: run_all.bat 2026-06-29
    goto :son
)

set SNAP=%~1
set CFG=config_%SNAP%.py
set OUT=..\out_%SNAP%

if not exist "%CFG%" (
    echo ERROR: %CFG% not found.
    goto :son
)

if not exist "%OUT%" mkdir "%OUT%"

REM --- global env: no bytecode, headless matplotlib ----------------
set PYTHONDONTWRITEBYTECODE=1
set MPLBACKEND=Agg

REM --- activate config ------------------------------------------------
call :clean_cache
copy /Y "%CFG%" config.py > nul

echo.
echo ===================================================================
echo  Snapshot : %SNAP%
echo  Config   : %CFG%
echo  Output   : %OUT%\
echo ===================================================================
findstr /C:"FETCH_DATE" config.py
findstr /C:"%SNAP%" config.py > nul
if errorlevel 1 (
    echo.
    echo ERROR: config.py does not contain "%SNAP%" -- wrong config may have been copied.
    goto :son
)
echo.

REM --- manifest -------------------------------------------------------
(
    echo run_all.bat
    echo snapshot      : %SNAP%
    echo config        : %CFG%
    echo run time      : %DATE% %TIME%
    echo working dir   : %CD%
    echo python        :
    python --version 2>&1
    echo ---- config.py ----
    type config.py
) > "%OUT%\_manifest.txt"

REM --- 1. IV.A, IV.B, Table II
call :run IVA-IVB_enrichment_and_composition_full "" IVA-IVB_enrichment_and_composition_full

REM --- 2. Group C provenance, all statuses (V.B, V.C)
call :run provenance_by_status "" provenance_by_status

REM --- 3. Group C provenance, Modified only (IV.E: CPE 100%)
call :run provenance_by_status "--status Modified" provenance_modified

REM --- 4. RQ chains: Analyzed ref + bootstrap + top-15 detail
call :run IVC-IVD_ExploitabilityProfileOfExcludes "--bootstrap 1000 --top 15 --top-detail" rq_A

REM --- 5. RQ chains: Analyzed+Modified ref
call :run IVC-IVD_ExploitabilityProfileOfExcludes "--bootstrap 1000 --reference-status Analyzed,Modified" rq_AM

REM --- 6. RQ chains: WordPress sources excluded
call :run IVC-IVD_ExploitabilityProfileOfExcludes "--bootstrap 1000 --exclude-sources Patchstack,Wordfence" rq_noWP

REM --- 7. Group D status breakdown
call :run IVE_group_d_status_breakdown "" IVE_group_d_status_breakdown

REM --- 8. WordPress union share
call :run wordpress_union_share "" wordpress_union_share

REM --- 9. Verification (IV.A/IV.B via independent code path)
call :run verify_enrichment_and_composition "" verify_enrichment_and_composition

REM --- 10. Cross-retrieval consistency (III.C / IV.E)
call :run cross_retrieval_check "" cross_retrieval_check

REM --- 11. Per-CVE status transitions (only meaningful for the second snapshot)
if not "%SNAP%"=="2026-06-29" (
    call :run status_transitions "--group A --show-ids 20" transitions_A
    call :run status_transitions "--group C --pub-end 2026-02-28 --show-ids 5" transitions_C
    call :run status_transitions "--group D --show-ids 20" transitions_D
) else (
    echo   SKIPPED: status_transitions ^(baseline snapshot, nothing to compare^)
)

REM --- 12. Survival curves (Fig. 2, Fig. 3)
call :run plot_survival_curves "" plot_survival_curves

echo.
echo ===================================================================
echo  Done. Outputs: %OUT%\
echo ===================================================================
dir /b "%OUT%"
echo.
goto :son

REM -------------------------------------------------------------------
REM  :clean_cache   -- before every script
REM -------------------------------------------------------------------
:clean_cache
if exist __pycache__ rmdir /s /q __pycache__
set PYTHONDONTWRITEBYTECODE=1
goto :eof

REM -------------------------------------------------------------------
REM  :run  <script_name_without_py>  "<arguments>"  <output_name>
REM -------------------------------------------------------------------
:run
set SCRIPT=%~1
set ARGS=%~2
set NAME=%~3
call :clean_cache
if exist "%SCRIPT%.py" (
    echo   [%NAME%] python %SCRIPT%.py %ARGS%
    python "%SCRIPT%.py" %ARGS% > "%OUT%\%NAME%.txt" 2>&1
    if errorlevel 1 (
        echo      WARNING: exited with error -- %OUT%\%NAME%.txt
    )
) else (
    echo   SKIPPED: %SCRIPT%.py not found
    echo SKIPPED: %SCRIPT%.py not found > "%OUT%\%NAME%.txt"
)
goto :eof

:son
endlocal
pause
