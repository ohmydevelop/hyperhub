<#
.SYNOPSIS
Builds HyperHub on a remote Linux host, installs it, and runs integrity smoke checks.

.DESCRIPTION
Archives a committed Git revision and transfers it with
`hyperhub.exe run scp`, invokes the remote build through `hyperhub.exe run ssh`, installs
the single-file CLI, and verifies that the embedded Agent is intact. The remote host must
already provide the Linux build prerequisites documented in third_party/frida/README.md.
The default x86_64 remote build obtains the pinned patched Frida source recipe there.
A native ARM64 remote host requires an explicit source-built Core/Gum SDK pair.

.PARAMETER RemoteHost
SSH destination such as user@linux-host.

.PARAMETER SourceRef
Committed Git revision to build. Defaults to HEAD; uncommitted working-tree changes are
not included.

.PARAMETER InstallPath
Absolute destination on Linux. Defaults to /bin/hyperhub.

.PARAMETER RustToolchain
Optional Rust toolchain used only for the remote build, such as 1.88.0-x86_64-unknown-linux-gnu.

.EXAMPLE
.\scripts\build-remote-linux.ps1 -RemoteHost user@linux-host
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [Alias('Host')]
  [ValidatePattern('^(?:[A-Za-z0-9][A-Za-z0-9._-]*@)?[A-Za-z0-9][A-Za-z0-9._-]*$')]
  [string]$RemoteHost,

  [ValidateRange(1, 65535)]
  [int]$Port = 22,

  [string]$IdentityFile,

  [string]$PasswordFile,

  [string]$HyperHub,

  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]*$')]
  [string]$SourceRef = 'HEAD',

  [ValidatePattern('^/[A-Za-z0-9._/-]+$')]
  [string]$InstallPath = '/bin/hyperhub',

  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
  [string]$RustToolchain,

  [string]$LinuxFridaGumRoot,

  [string]$LinuxFridaCoreRoot,

  [switch]$KeepRemote
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
  & $Program @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$Program failed with exit code $LASTEXITCODE"
  }
}

function Invoke-CapturedChecked([string]$Program, [string[]]$Arguments) {
  $output = & $Program @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$Program failed with exit code $LASTEXITCODE"
  }
  return ($output | Out-String).Trim()
}

function Resolve-ExistingFile([string]$Path, [string]$Description) {
  $resolved = [IO.Path]::GetFullPath($Path)
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "$Description was not found: $resolved"
  }
  return $resolved
}

function Assert-LocalTempPath([string]$Path) {
  $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
  $resolved = [IO.Path]::GetFullPath($Path)
  if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "refusing to remove a path outside the local temporary directory: $resolved"
  }
}

if (-not $IsWindows) {
  throw 'This orchestrator must run on Windows because it launches hyperhub.exe.'
}
if ([bool]$LinuxFridaGumRoot -ne [bool]$LinuxFridaCoreRoot) {
  throw 'Custom Linux Frida SDKs require both -LinuxFridaGumRoot and -LinuxFridaCoreRoot.'
}
if ($InstallPath -eq '/' -or $InstallPath.EndsWith('/')) {
  throw "InstallPath must name a file: $InstallPath"
}

$remoteRoot = $null
$remoteRootCreated = $false
$hyperhubRun = $null
$sshOptions = $null

Push-Location $repoRoot
$localTemp = Join-Path ([IO.Path]::GetTempPath()) ("hyperhub-remote-linux-" + [Guid]::NewGuid().ToString('N'))
try {
  $HyperHub = if ($HyperHub) {
    Resolve-ExistingFile $HyperHub 'HyperHub CLI'
  } else {
    Resolve-ExistingFile (Join-Path $repoRoot 'target\release\hyperhub.exe') 'HyperHub CLI'
  }
  $PasswordFile = if ($PasswordFile) {
    Resolve-ExistingFile $PasswordFile 'HyperHub password file'
  } else {
    Resolve-ExistingFile (Join-Path $repoRoot '.passwd') 'default HyperHub password file'
  }
  if ($IdentityFile) {
    $IdentityFile = Resolve-ExistingFile $IdentityFile 'SSH identity file'
  }
  foreach ($command in @('git', 'ssh', 'scp')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
      throw "required command was not found in PATH: $command"
    }
  }

  $commit = Invoke-CapturedChecked 'git' @('rev-parse', '--verify', "${SourceRef}^{commit}")
  New-Item -ItemType Directory -Path $localTemp | Out-Null
  $archive = Join-Path $localTemp 'hyperhub-src.tar'
  $helper = Resolve-ExistingFile (Join-Path $PSScriptRoot 'build-install-linux.sh') 'remote Linux build helper'
  $token = [Guid]::NewGuid().ToString('N')
  $remoteRoot = "/tmp/hyperhub-remote-$token"
  $remoteArchive = "$remoteRoot/source.tar"
  $remoteHelper = "$remoteRoot/build-install.sh"
  $remoteGumArchive = "$remoteRoot/frida-gum.tar.xz"
  $remoteCoreArchive = "$remoteRoot/frida-core.tar.xz"

  Write-Host "Archiving committed source ref $SourceRef..."
  Invoke-Checked 'git' @('archive', '--format=tar', "--output=$archive", $commit)

  Write-Host 'Ensuring the local HyperHub Serve is running...'
  $instanceHome = if ($env:HYPERHUB_HOME) { $env:HYPERHUB_HOME } else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.hyperhub' }
  $apiKeyPath = Join-Path (Join-Path $instanceHome 'runtime') 'api-key'
  if (Test-Path -LiteralPath $apiKeyPath -PathType Leaf) {
    Invoke-Checked $HyperHub @('start')
  } else {
    Invoke-Checked $HyperHub @('start', '--admin-password-file', $PasswordFile)
  }

  $hyperhubRun = @('run', '--')
  $scpOptions = @('-P', $Port.ToString())
  $sshOptions = @('-p', $Port.ToString())
  if ($IdentityFile) {
    $scpOptions += @('-i', $IdentityFile)
    $sshOptions += @('-i', $IdentityFile)
  }

  $remoteArch = Invoke-CapturedChecked $HyperHub ($hyperhubRun + @('ssh') + $sshOptions + @(
      $RemoteHost,
      'uname',
      '-m'
    ))
  if ($remoteArch -notin @('x86_64', 'aarch64', 'arm64')) {
    throw "unsupported remote Linux architecture: $remoteArch"
  }
  if ($remoteArch -ne 'x86_64' -and -not $LinuxFridaGumRoot) {
    throw 'Native ARM64 source builds require -LinuxFridaGumRoot and -LinuxFridaCoreRoot from the pinned x86_64 source recipe.'
  }
  $transfers = @(@($archive, $remoteArchive), @($helper, $remoteHelper))
  if ($LinuxFridaGumRoot) {
    if (-not (Get-Command 'tar' -ErrorAction SilentlyContinue)) {
      throw 'tar is required to transfer the explicit Linux SDK pair.'
    }
    foreach ($sdk in @(
        @('gum', $LinuxFridaGumRoot, $remoteGumArchive),
        @('core', $LinuxFridaCoreRoot, $remoteCoreArchive)
      )) {
      $sdkRoot = [IO.Path]::GetFullPath($sdk[1])
      foreach ($filename in @("frida-$($sdk[0]).h", "libfrida-$($sdk[0]).a", 'hyperhub-frida-sdk.json')) {
        $null = Resolve-ExistingFile (Join-Path $sdkRoot $filename) 'source-built Linux SDK input'
      }
      $sdkArchive = Join-Path $localTemp ("frida-" + $sdk[0] + '.tar.xz')
      Invoke-Checked 'tar' @('-cJf', $sdkArchive, '-C', $sdkRoot, '.')
      $transfers += ,@($sdkArchive, $sdk[2])
    }
  }

  Invoke-Checked $HyperHub ($hyperhubRun + @('ssh') + $sshOptions + @(
      $RemoteHost,
      'mkdir',
      '-m',
      '0700',
      $remoteRoot
    ))
  $remoteRootCreated = $true
  Write-Host "Uploading source and any explicit source-built SDK inputs to $RemoteHost..."
  foreach ($transfer in $transfers) {
    Invoke-Checked $HyperHub ($hyperhubRun + @('scp') + $scpOptions + @(
        $transfer[0],
        "${RemoteHost}:$($transfer[1])"
      ))
  }

  $keepFlag = if ($KeepRemote) { '1' } else { '0' }
  Write-Host "Building on $RemoteHost and installing to $InstallPath..."
  $remoteBuildArguments = @($RemoteHost)
  if ($RustToolchain) {
    $remoteBuildArguments += @('env', "RUSTUP_TOOLCHAIN=$RustToolchain")
  }
  $remoteBuildArguments += @(
    'bash',
    $remoteHelper,
    $remoteRoot,
    $InstallPath,
    $keepFlag
  )
  Invoke-Checked $HyperHub ($hyperhubRun + @('ssh') + $sshOptions + $remoteBuildArguments)

  Write-Host "HyperHub is installed and verified on ${RemoteHost}:$InstallPath"
  if ($KeepRemote) {
    Write-Host "Remote build directory retained at $remoteRoot"
  }
}
catch {
  if ($remoteRootCreated -and -not $KeepRemote -and $hyperhubRun -and $sshOptions) {
    try {
      Invoke-Checked $HyperHub ($hyperhubRun + @('ssh') + $sshOptions + @(
          $RemoteHost,
          'rm',
          '-rf',
          '--',
          $remoteRoot
        ))
    }
    catch {
      Write-Warning "Remote cleanup failed for ${RemoteHost}:$remoteRoot"
    }
  }
  throw
}
finally {
  Pop-Location
  if (Test-Path -LiteralPath $localTemp) {
    Assert-LocalTempPath $localTemp
    Remove-Item -LiteralPath $localTemp -Recurse -Force
  }
}
