param(
    [switch]$UseVenv
)

function Get-UsablePythonCommand {
    param(
        [switch]$PreferVenv
    )

    $candidates = @()
    $venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue

    if ($PreferVenv -and (Test-Path $venvPython)) {
        $candidates += @{
            Label = "venv"
            Command = $venvPython
            RunArgs = @()
            ProbeArgs = @("-c", "import sys; print(sys.executable)")
        }
    }

    if ($pyLauncher) {
        $candidates += @{
            Label = "py-launcher"
            Command = $pyLauncher.Source
            RunArgs = @("-3")
            ProbeArgs = @("-3", "-c", "import sys; print(sys.executable)")
        }
    }

    if (-not $PreferVenv -and (Test-Path $venvPython)) {
        $candidates += @{
            Label = "venv"
            Command = $venvPython
            RunArgs = @()
            ProbeArgs = @("-c", "import sys; print(sys.executable)")
        }
    }

    foreach ($candidate in $candidates) {
        try {
            & $candidate.Command @($candidate.ProbeArgs) *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        } catch {
        }
    }

    return $null
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$appPath = Join-Path $root "akilli_rapor\web_app.py"
$python = Get-UsablePythonCommand -PreferVenv:$UseVenv

if (-not $python) {
    Write-Error "Calisan bir Python bulunamadi. Once Python 3 kurun veya .\setup_venv.ps1 ile sanal ortami yeniden olusturun."
    exit 1
}

& $python.Command @($python.RunArgs) $appPath
exit $LASTEXITCODE
