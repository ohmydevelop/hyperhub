[CmdletBinding()]
param([string]$HyperHub = (Join-Path $PSScriptRoot '..\target\release\hyperhub.exe'))
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Run this installer regression on Windows.' }
$HyperHub = (Resolve-Path -LiteralPath $HyperHub).Path
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('hh-dev-install-' + [guid]::NewGuid().ToString('N'))
$saved = @{}
foreach ($name in @('USERPROFILE', 'HYPERHUB_VERSION', 'HYPERHUB_INSTALL_DIR', 'HYPERHUB_HOME')) {
  $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$previousUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$previousProcessPath = $env:Path
try {
  $homeDirectory = Join-Path $temporary 'home'
  $fixture = Join-Path $temporary 'fixture'
  New-Item -ItemType Directory -Force -Path $homeDirectory, $fixture | Out-Null
  Copy-Item -LiteralPath $HyperHub -Destination (Join-Path $fixture 'hyperhub.exe')
  $script:developmentFixtureZip = Join-Path $temporary 'fixture.zip'
  Compress-Archive -LiteralPath (Join-Path $fixture 'hyperhub.exe') -DestinationPath $script:developmentFixtureZip
  function Invoke-WebRequest {
    param([switch]$UseBasicParsing, [string]$Uri, [string]$OutFile)
    if ($Uri -notmatch '/releases/download/v0\.3\.0-alpha\.1/hyperhub-windows-x64\.zip$') {
      throw "Unexpected development download URL: $Uri"
    }
    Copy-Item -LiteralPath $script:developmentFixtureZip -Destination $OutFile
  }
  $env:USERPROFILE = $homeDirectory
  $env:HYPERHUB_VERSION = 'v0.3.0-alpha.1'
  $env:HYPERHUB_HOME = Join-Path $homeDirectory '.hyperhub-dev'
  Remove-Item Env:HYPERHUB_INSTALL_DIR -ErrorAction SilentlyContinue
  $stable = Join-Path $homeDirectory '.hyperhub\bin\hyperhub.exe'
  New-Item -ItemType Directory -Force -Path (Split-Path $stable) | Out-Null
  [IO.File]::WriteAllText($stable, 'stable installation sentinel')
  $sentinelHash = (Get-FileHash -LiteralPath $stable -Algorithm SHA256).Hash
  & (Join-Path $PSScriptRoot 'install.ps1')
  $installed = Join-Path $homeDirectory '.hyperhub-dev\bin\0.3.0-alpha.1\hyperhub.exe'
  if (-not (Test-Path -LiteralPath $installed)) { throw 'Development install path is incorrect.' }
  if ((Get-FileHash -LiteralPath $installed).Hash -ne (Get-FileHash -LiteralPath $HyperHub).Hash) {
    throw 'Installed executable differs from fixture.'
  }
  if ((Get-FileHash -LiteralPath $stable).Hash -ne $sentinelHash) { throw 'Stable install changed.' }
  if ([Environment]::GetEnvironmentVariable('Path', 'User') -cne $previousUserPath) {
    throw 'Development installer changed user PATH.'
  }
  if ($env:Path -cne $previousProcessPath) { throw 'Development installer changed process PATH.' }
  if (Test-Path -LiteralPath (Join-Path (Split-Path $stable) 'hsh.cmd')) { throw 'Stable shortcut changed.' }
  Write-Host 'Development installer isolation passed.'
} finally {
  foreach ($entry in $saved.GetEnumerator()) {
    [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
  }
  # This regression runs on a disposable CI account; restore PATH even if a regression occurs.
  if ([Environment]::GetEnvironmentVariable('Path', 'User') -cne $previousUserPath) {
    [Environment]::SetEnvironmentVariable('Path', $previousUserPath, 'User')
  }
  $env:Path = $previousProcessPath
  Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
