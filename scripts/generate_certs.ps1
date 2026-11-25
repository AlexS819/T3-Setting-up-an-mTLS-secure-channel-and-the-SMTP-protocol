<#
.SYNOPSIS
    Генерація локального PKI для Secure Alert Gateway (Windows / PowerShell).

.DESCRIPTION
    Скрипт викликає Go-генератор ./cmd/gencerts, тому openssl не потрібен.
    Еквівалентний openssl-варіант лежить у scripts/generate_certs.sh.

.EXAMPLE
    .\scripts\generate_certs.ps1
    .\scripts\generate_certs.ps1 -Force -Days 730
#>
param(
    [string]$Dir = 'certs',
    [int]$Days = 365,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $goArgs = @('run', './cmd/gencerts', '-dir', $Dir, '-days', $Days)
    if ($Force) { $goArgs += '-force' }
    & go @goArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Генерація сертифікатів завершилась з кодом $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
