[CmdletBinding()]
param(
  [string]$FridaGumRoot,
  [switch]$SkipTests,
  [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fridaGumVersion = '17.17.0'
$archiveName = "frida-gum-devkit-$fridaGumVersion-windows-x86_64.tar.xz"
$archiveUrl = "https://github.com/frida/frida/releases/download/$fridaGumVersion/$archiveName"
$archiveSha256 = '7C0166AFE681395ACB523FC3044A8B9434C9166997F6FDBA43FD3631ABAA6CA0'

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
  & $Program @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$Program failed with exit code $LASTEXITCODE"
  }
}

function Test-FileLocked([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return $false
  }
  try {
    $stream = [IO.File]::Open(
      $Path,
      [IO.FileMode]::Open,
      [IO.FileAccess]::ReadWrite,
      [IO.FileShare]::None
    )
    $stream.Dispose()
    return $false
  }
  catch [IO.IOException] {
    return $true
  }
  catch [UnauthorizedAccessException] {
    return $true
  }
}

function Stop-AgentConsumers([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return
  }
  $resolvedAgent = [IO.Path]::GetFullPath($Path)
  $consumers = @(Get-Process | ForEach-Object {
      $candidate = $_
      if ($candidate.Id -eq $PID) { return }
      try {
        foreach ($module in $candidate.Modules) {
          if ([string]::Equals(
              [IO.Path]::GetFullPath($module.FileName),
              $resolvedAgent,
              [StringComparison]::OrdinalIgnoreCase
            )) {
            $candidate
            break
          }
        }
      }
      catch {
        # Protected processes do not expose their module list.
      }
    })
  foreach ($consumer in $consumers) {
    Write-Warning "Stopping process using Gum Agent: $($consumer.ProcessName) (PID $($consumer.Id))"
    Stop-Process -Id $consumer.Id -Force -ErrorAction Stop
    Wait-Process -Id $consumer.Id -Timeout 5 -ErrorAction SilentlyContinue
  }
  if (Test-FileLocked $resolvedAgent) {
    throw "Gum Agent remains locked: $resolvedAgent"
  }
}

function Resolve-FridaGumRoot {
  if ($FridaGumRoot) {
    return [IO.Path]::GetFullPath($FridaGumRoot)
  }
  if ($env:HYPERHUB_FRIDA_GUM_ROOT) {
    return [IO.Path]::GetFullPath($env:HYPERHUB_FRIDA_GUM_ROOT)
  }
  return Join-Path $repoRoot ".deps\frida-gum\$fridaGumVersion\windows-x64"
}

function Install-FridaGum([string]$Destination) {
  $library = Join-Path $Destination 'frida-gum.lib'
  if (Test-Path -LiteralPath $library -PathType Leaf) {
    return
  }
  if ($FridaGumRoot -or $env:HYPERHUB_FRIDA_GUM_ROOT) {
    throw "Frida Gum devkit is incomplete at $Destination; expected $library"
  }

  $cache = Join-Path $repoRoot '.cache\frida'
  New-Item -ItemType Directory -Force -Path $cache | Out-Null
  $archive = Join-Path $cache $archiveName
  if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    Write-Host "Downloading Frida Gum $fridaGumVersion..."
    Invoke-WebRequest -Uri $archiveUrl -OutFile $archive
  }
  $actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
  if ($actualHash -ne $archiveSha256) {
    throw "Frida Gum SHA-256 mismatch: expected $archiveSha256, got $actualHash"
  }

  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  Write-Host "Extracting verified Frida Gum $fridaGumVersion into $Destination"
  Invoke-Checked 'tar' @('-xJf', $archive, '-C', $Destination)
  if (-not (Test-Path -LiteralPath $library -PathType Leaf)) {
    throw "Frida Gum extraction did not produce $library"
  }
}

if (-not $IsWindows) {
  throw 'The current Gum Agent build supports Windows x64 only.'
}

Push-Location $repoRoot
$previousGumRoot = $env:HYPERHUB_FRIDA_GUM_ROOT
$previousEmbeddedAgent = $env:HYPERHUB_EMBEDDED_AGENT_PATH
try {
  $resolvedGumRoot = Resolve-FridaGumRoot
  Install-FridaGum $resolvedGumRoot
  $env:HYPERHUB_FRIDA_GUM_ROOT = $resolvedGumRoot

  $cli = Join-Path $repoRoot 'target\release\hyperhub.exe'
  $agent = Join-Path $repoRoot 'target\release\hyperhub_gum_agent.dll'
  if (Test-FileLocked $agent) {
    Stop-AgentConsumers $agent
  }
  if (Test-FileLocked $cli) {
    throw "HyperHub CLI is running and must be stopped before building: $cli"
  }

  if ($Clean) {
    Invoke-Checked 'cargo' @('clean')
  }

  if (-not $SkipTests) {
    Write-Host 'Running workspace tests...'
    Invoke-Checked 'cargo' @('test', '--workspace', '--all-targets', '--locked')
    Write-Host 'Running Gum Agent tests...'
    Invoke-Checked 'cargo' @(
      'test', '--locked', '--release',
      '-p', 'hyperhub-agent-core', '--features', 'gum-agent'
    )
  }

  Write-Host 'Building Rust Frida Gum Agent for embedding...'
  Invoke-Checked 'cargo' @(
    'build', '--release', '--locked',
    '-p', 'hyperhub-agent-core', '--features', 'gum-agent'
  )
  $env:HYPERHUB_EMBEDDED_AGENT_PATH = $agent
  if (-not $SkipTests) {
    Write-Host 'Testing embedded Agent build...'
    Invoke-Checked 'cargo' @(
      'test', '--locked', '-p', 'hyperhub',
      '--no-default-features', '--features', 'embedded-agent', 'embedded_'
    )
  }
  Write-Host 'Building single-file HyperHub CLI...'
  Invoke-Checked 'cargo' @(
    'build', '--release', '--locked', '-p', 'hyperhub',
    '--no-default-features', '--features', 'embedded-agent'
  )

  foreach ($output in @($cli, $agent)) {
    if (-not (Test-Path -LiteralPath $output -PathType Leaf)) {
      throw "build output was not produced: $output"
    }
  }
  Write-Host 'Single-file build complete:'
  Write-Host "  $cli"
  Write-Host "Agent embedded from intermediate artifact:"
  Write-Host "  $agent"
}
finally {
  $env:HYPERHUB_FRIDA_GUM_ROOT = $previousGumRoot
  $env:HYPERHUB_EMBEDDED_AGENT_PATH = $previousEmbeddedAgent
  Pop-Location
}
