param(
    [switch]$InstallRequirements,
    [switch]$UpgradePip
)

function Get-BasePythonCommand {
    $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        try {
            & $pyLauncher.Source -3 -c "import sys; print(sys.executable)" *> $null
            if ($LASTEXITCODE -eq 0) {
                return @{
                    Command = $pyLauncher.Source
                    Prefix = @("-3")
                }
            }
        } catch {
        }
    }

    return $null
}

$python = Get-BasePythonCommand
$venvPath = Join-Path $PSScriptRoot ".venv"
$requirementsPath = Join-Path $PSScriptRoot "akilli_rapor\requirements.txt"

if (-not $python) {
    Write-Error "Python bulunamadi. Once Python 3 kurun; ardindan bu script sanal ortami olusturabilir."
    exit 1
}

& $python.Command @($python.Prefix) -m venv --copies $venvPath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$venvPython = Join-Path $venvPath "Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Error "Sanal ortam olusturuldu ancak venv Python bulunamadi: $venvPython"
    exit 1
}

if ($UpgradePip) {
    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

if ($InstallRequirements) {
    & $venvPython -m pip install -r $requirementsPath
    exit $LASTEXITCODE
}
