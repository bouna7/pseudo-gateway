# Installe le binaire pseudo-gateway sur Windows (x64 ou ARM64).
#
#   irm https://github.com/bouna7/pseudo-gateway/releases/latest/download/install.ps1 | iex
#
# Variables : $env:VERSION (ex. v0.2.0, défaut : dernière release),
#             $env:INSTALL_DIR (défaut : %LOCALAPPDATA%\pseudo-gateway).
$ErrorActionPreference = 'Stop'

$repo = 'bouna7/pseudo-gateway'
$installDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'pseudo-gateway' }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'aarch64' }
    default { throw "Architecture non prise en charge : $($env:PROCESSOR_ARCHITECTURE)" }
}
$asset = "pseudo-gateway-$arch-pc-windows-msvc"
$base = if ($env:VERSION) { "https://github.com/$repo/releases/download/$($env:VERSION)" } else { "https://github.com/$repo/releases/latest/download" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Téléchargement de $asset.zip…"
    $zip = Join-Path $tmp "$asset.zip"
    $sums = Join-Path $tmp 'SHA256SUMS'
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset.zip" -OutFile $zip
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums

    $line = Get-Content $sums | Where-Object { $_ -match " $([regex]::Escape("$asset.zip"))$" } | Select-Object -First 1
    $expected = if ($line) { ($line -split '\s+')[0] } else { '' }
    $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
    if (-not $expected -or $expected -ne $actual) { throw 'Empreinte SHA-256 invalide — installation annulée.' }

    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Copy-Item (Join-Path $tmp "$asset\pseudo-gateway.exe") $installDir -Force
    Copy-Item (Join-Path $tmp "$asset\.env.example") $installDir -Force
} finally {
    Remove-Item -Recurse -Force $tmp
}

$exe = Join-Path $installDir 'pseudo-gateway.exe'
Write-Host "Installé : $exe ($(& $exe --version))"
if (($env:Path -split ';') -notcontains $installDir) {
    Write-Host "Pour l'appeler depuis n'importe où, ajoutez $installDir à votre PATH."
}
Write-Host @"

Démarrage rapide (dans le dossier de votre choix) :
  & '$exe' gen-keys | Out-File -Encoding ascii .env
  & '$exe'            # API sur http://localhost:8080
"@
