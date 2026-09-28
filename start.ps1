# JOCKY launcher (Windows). Usage: .\start.ps1 [--dev] [--new-token] [--rebuild]
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)
$py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { throw "Python 3.10+ is required: https://www.python.org/downloads/" }
& $py start.py @args
exit $LASTEXITCODE
