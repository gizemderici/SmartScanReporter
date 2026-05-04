param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

function Get-UsablePythonCommand {
    $candidates = @()

    $venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        $candidates += @{
            Label = "venv"
            Command = $venvPython
            Arguments = @("-c", "import sys; print(sys.executable)")
        }
    }

    $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $candidates += @{
            Label = "py-launcher"
            Command = $pyLauncher.Source
            Arguments = @("-3", "-c", "import sys; print(sys.executable)")
        }
    }

    foreach ($candidate in $candidates) {
        try {
            & $candidate.Command @($candidate.Arguments) *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        } catch {
        }
    }

    return $null
}

$pythonCandidate = Get-UsablePythonCommand
if (-not $pythonCandidate) {
    Write-Error "Calisan bir Python bulunamadi. Once sistem Python kurun veya .\setup_venv.ps1 ile sanal ortami yeniden olusturun."
    exit 1
}

if ($pythonCandidate.Label -eq "py-launcher") {
    & $pythonCandidate.Command -3 @Args
} else {
    & $pythonCandidate.Command @Args
}
exit $LASTEXITCODE
