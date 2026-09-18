[CmdletBinding()]
param(
  [ValidateSet('windows-x64')]
  [string]$Target = 'windows-x64',
  [string]$Version,
  [string]$FridaGumRoot,
  [string]$OutputRoot,
  [switch]$SkipTests,
  [switch]$Clean,
  [switch]$KeepStaging
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildScript = Join-Path $PSScriptRoot 'build.ps1'

function Require-File([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Description was not produced: $Path"
  }
}

if (-not $IsWindows) {
  throw 'The current release target is windows-x64 and must be built on Windows.'
}
Require-File $buildScript 'HyperHub build script'

Push-Location $repoRoot
try {
  if (-not $Version) {
    $metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $Version = ($metadata.packages | Where-Object name -eq 'hyperhub' | Select-Object -First 1).version
  }
  if (-not $Version -or $Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$') {
    throw "invalid release version: $Version"
  }
  $OutputRoot = if ($OutputRoot) {
    [IO.Path]::GetFullPath($OutputRoot)
  } else {
    Join-Path $repoRoot 'dist'
  }

  $buildArgs = @{}
  if ($FridaGumRoot) { $buildArgs.FridaGumRoot = $FridaGumRoot }
  if ($SkipTests) { $buildArgs.SkipTests = $true }
  if ($Clean) { $buildArgs.Clean = $true }
  & $buildScript @buildArgs
  if (-not $?) { throw 'HyperHub build failed' }

  $packageName = "hyperhub-v$Version-windows-x64"
  $packageDir = Join-Path $OutputRoot $packageName
  $archive = Join-Path $OutputRoot "$packageName.zip"
  foreach ($path in @($packageDir, $archive)) {
    $resolved = [IO.Path]::GetFullPath($path)
    if (-not $resolved.StartsWith([IO.Path]::GetFullPath($OutputRoot), [StringComparison]::OrdinalIgnoreCase)) {
      throw "unsafe release path: $resolved"
    }
    if (Test-Path -LiteralPath $resolved) {
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }

  $cli = Join-Path $repoRoot 'target\release\hyperhub.exe'
  $license = Join-Path $repoRoot 'LICENSE'
  $fridaLicense = Join-Path $repoRoot 'third_party\frida-gum\COPYING'
  Require-File $cli 'HyperHub CLI'
  Require-File $license 'HyperHub license'
  Require-File $fridaLicense 'Frida Gum license'

  New-Item -ItemType Directory -Force -Path $packageDir | Out-Null
  Copy-Item -LiteralPath $cli -Destination $packageDir
  Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') -Destination $packageDir
  Copy-Item -LiteralPath $license -Destination (Join-Path $packageDir 'LICENSE')
  Copy-Item -LiteralPath $fridaLicense -Destination (Join-Path $packageDir 'LICENSE-FRIDA-GUM.txt')

  $runtimeFiles = @(Get-ChildItem -LiteralPath $packageDir -File | Where-Object {
    $_.Extension -in @('.exe', '.dll')
  } | Select-Object -ExpandProperty Name | Sort-Object)
  $expected = @('hyperhub.exe')
  if (Compare-Object $expected $runtimeFiles) {
    throw "release must contain exactly: $($expected -join ', ')"
  }

  & (Join-Path $packageDir 'hyperhub.exe') --help
  if ($LASTEXITCODE -ne 0) { throw 'packaged HyperHub CLI smoke test failed' }
  $doctor = & (Join-Path $packageDir 'hyperhub.exe') doctor | Out-String
  if ($LASTEXITCODE -ne 0 -or $doctor -notmatch 'agent_runtime=embedded-verified') {
    throw 'packaged HyperHub CLI does not contain the verified embedded Agent'
  }
  $manifest = Get-ChildItem -LiteralPath $packageDir -Recurse -File |
    Sort-Object FullName |
    ForEach-Object {
      $relative = [IO.Path]::GetRelativePath($packageDir, $_.FullName).Replace('\', '/')
      "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
    }
  Set-Content -LiteralPath (Join-Path $packageDir 'MANIFEST.sha256') -Value $manifest -Encoding ascii

  New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
  Compress-Archive -LiteralPath $packageDir -DestinationPath $archive -CompressionLevel Optimal
  Write-Host "Release package: $archive"
  Write-Host "SHA-256: $((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash)"
  if (-not $KeepStaging) {
    Remove-Item -LiteralPath $packageDir -Recurse -Force
  }
}
finally {
  Pop-Location
}
