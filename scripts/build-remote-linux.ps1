<#
.SYNOPSIS
Builds HyperHub on a remote Linux host, installs it, and runs integrity smoke checks.

.DESCRIPTION
Archives a committed Git revision, transfers it and verified Linux Frida devkits with
`hyperhub.exe run scp`, invokes the remote build through `hyperhub.exe run ssh`, installs
the single-file CLI, and verifies that the embedded Agent is intact. The remote host must
already provide the Linux build toolchain documented in README.md.

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

  [switch]$KeepRemote
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fridaVersion = '17.17.0'

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

function Resolve-FridaArchive(
  [string]$Kind,
  [string]$Platform,
  [string]$ExpectedSha256
) {
  $cache = Join-Path $repoRoot '.cache\frida'
  New-Item -ItemType Directory -Force -Path $cache | Out-Null
  $name = "frida-$Kind-devkit-$fridaVersion-$Platform.tar.xz"
  $archive = Join-Path $cache $name
  if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    $url = "https://github.com/frida/frida/releases/download/$fridaVersion/$name"
    Write-Host "Downloading $name..."
    Invoke-WebRequest -Uri $url -OutFile $archive
  }
  $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
  if ($actual -ne $ExpectedSha256) {
    throw "$name SHA-256 mismatch: expected $ExpectedSha256, got $actual"
  }
  return $archive
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
  Invoke-Checked $HyperHub @('start', '--password-file', $PasswordFile)

  $hyperhubRun = @('run', '--password-file', $PasswordFile, '--')
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
  switch ($remoteArch) {
    'x86_64' {
      $platform = 'linux-x86_64'
      $gumSha256 = '0987DD51E9901A6DDDD9D55BC9EF02CD90D95012A4947E29DAB942EC7F5348B7'
      $coreSha256 = '483E1A25945CEBAA69E61C09D7804692C42D234CAB0C58261A73382163027A2E'
    }
    { $_ -in @('aarch64', 'arm64') } {
      $platform = 'linux-arm64'
      $gumSha256 = 'A035CB1F9F58F03822FA87D6DD578BBADB7C3452BC1B8C08EE31C1F14E29025F'
      $coreSha256 = '93ACE484ED610961BA153B176C6363A5AC598A1DB3B245EF785175A8229568B0'
    }
    default { throw "unsupported remote Linux architecture: $remoteArch" }
  }
  $gumArchive = Resolve-FridaArchive 'gum' $platform $gumSha256
  $coreArchive = Resolve-FridaArchive 'core' $platform $coreSha256

  Invoke-Checked $HyperHub ($hyperhubRun + @('ssh') + $sshOptions + @(
      $RemoteHost,
      'mkdir',
      '-m',
      '0700',
      $remoteRoot
    ))
  $remoteRootCreated = $true
  Write-Host "Uploading source and verified $platform Frida devkits to $RemoteHost..."
  foreach ($transfer in @(
      @($archive, $remoteArchive),
      @($helper, $remoteHelper),
      @($gumArchive, $remoteGumArchive),
      @($coreArchive, $remoteCoreArchive)
    )) {
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
