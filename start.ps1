# One-command SecureScan start for Windows.
# Uses backend\venv when present so you do not have to activate it first.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $root "backend\venv\Scripts\python.exe"
$launcher = Join-Path $root "backend\run_dev.py"

if (Test-Path $venvPython) {
    & $venvPython $launcher
} else {
    python $launcher
}
