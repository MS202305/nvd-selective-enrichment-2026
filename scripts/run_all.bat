@echo off
REM ===================================================================
REM  run_all.bat  <YYYY-MM-DD>
REM
REM  Verilen snapshot tarihine ait config'i etkinlestirir ve makaledeki
REM  TUM sayilari ureten scriptleri calistirir. Ciktilar:
REM      ..\out_<tarih>\<ad>.txt
REM
REM  KULLANIM (scripts\ dizininden):
REM      run_all.bat 2026-06-29
REM      run_all.bat 2026-09-01
REM
REM  Her script cagrisi oncesi __pycache__ silinir ve
REM  PYTHONDONTWRITEBYTECODE=1 ayarlanir (config.py degisimi cache'e
REM  takilmasin diye).
REM
REM  Kapsam (makale bolumu -> cikti dosyasi):
REM    IV.A, IV.B, Tablo II, V.B (excluded)  -> IVA-IVB_enrichment_and_composition_full.txt
REM    V.B, V.C (Group C, tum statuler)      -> provenance_by_status.txt
REM    IV.E (Modified CPE=100%)              -> provenance_modified.txt
REM    IV.C, IV.D, Tablo III, Tablo IV (A)   -> rq_A.txt
REM    IV.E, Tablo IV (A+M)                  -> rq_AM.txt
REM    IV.E, Tablo IV (non-WP)               -> rq_noWP.txt
REM    IV.E Group D                          -> IVE_group_d_status_breakdown.txt
REM    IV.E WordPress share                  -> wordpress_union_share.txt
REM    (dogrulama, IV.A/IV.B ikinci yol)     -> verify_enrichment_and_composition.txt
REM    III.C / IV.E cross-retrieval          -> cross_retrieval_check.txt
REM    IV.E per-CVE transitions (sadece Eyl) -> transitions_A.txt, transitions_C.txt, transitions_D.txt
REM    Fig. 2, Fig. 3                        -> plot_survival_curves.txt (+PNG/PDF)
REM ===================================================================

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo HATA: snapshot tarihi belirtilmedi.
    echo Kullanim: run_all.bat 2026-06-29
    goto :son
)

set SNAP=%~1
set CFG=config_%SNAP%.py
set OUT=..\out_%SNAP%

if not exist "%CFG%" (
    echo HATA: %CFG% bulunamadi.
    goto :son
)

if not exist "%OUT%" mkdir "%OUT%"

REM --- global env: bytecode yazma, matplotlib headless ----------------
set PYTHONDONTWRITEBYTECODE=1
set MPLBACKEND=Agg

REM --- activate config ------------------------------------------------
call :clean_cache
copy /Y "%CFG%" config.py > nul

echo.
echo ===================================================================
echo  Snapshot : %SNAP%
echo  Config   : %CFG%
echo  Cikti    : %OUT%\
echo ===================================================================
findstr /C:"FETCH_DATE" config.py
findstr /C:"%SNAP%" config.py > nul
if errorlevel 1 (
    echo.
    echo HATA: config.py icinde "%SNAP%" gecmiyor -- yanlis config kopyalanmis olabilir.
    goto :son
)
echo.

REM --- manifest -------------------------------------------------------
(
    echo run_all.bat
    echo snapshot      : %SNAP%
    echo config        : %CFG%
    echo calisma zamani: %DATE% %TIME%
    echo calisma dizini: %CD%
    echo python        :
    python --version 2>&1
    echo ---- config.py ----
    type config.py
) > "%OUT%\_manifest.txt"

REM --- 1. IV.A, IV.B, Tablo II
call :run IVA-IVB_enrichment_and_composition_full "" IVA-IVB_enrichment_and_composition_full

REM --- 2. Group C provenance, tum statuler (V.B, V.C)
call :run provenance_by_status "" provenance_by_status

REM --- 3. Group C provenance, sadece Modified (IV.E: CPE 100%)
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
    echo   ATLANDI: status_transitions ^(baseline snapshot, karsilastirma yok^)
)

REM --- 12. Survival curves (Fig. 2, Fig. 3)
call :run plot_survival_curves "" plot_survival_curves

echo.
echo ===================================================================
echo  Bitti. Ciktilar: %OUT%\
echo ===================================================================
dir /b "%OUT%"
echo.
goto :son

REM -------------------------------------------------------------------
REM  :clean_cache   -- her script oncesi
REM -------------------------------------------------------------------
:clean_cache
if exist __pycache__ rmdir /s /q __pycache__
set PYTHONDONTWRITEBYTECODE=1
goto :eof

REM -------------------------------------------------------------------
REM  :run  <script_adi_py_haric>  "<argumanlar>"  <cikti_adi>
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
        echo      UYARI: hata ile bitti -- %OUT%\%NAME%.txt
    )
) else (
    echo   ATLANDI: %SCRIPT%.py bulunamadi
    echo ATLANDI: %SCRIPT%.py bulunamadi > "%OUT%\%NAME%.txt"
)
goto :eof

:son
endlocal
pause
