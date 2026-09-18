$ErrorActionPreference = "Stop"

$repo = if ($env:HYPERHUB_REPO) { $env:HYPERHUB_REPO } else { "flash-dev-ctrl/hyperhub" }
$version = if ($env:HYPERHUB_VERSION) { $env:HYPERHUB_VERSION } else { "latest" }
$installDir = if ($env:HYPERHUB_INSTALL_DIR) { $env:HYPERHUB_INSTALL_DIR } else { Join-Path $env:USERPROFILE ".hyperhub\bin" }

if ([Environment]::Is64BitOperatingSystem -eq $false) {
  throw "HyperHub supports Windows x64 only"
}

$asset = "hyperhub-windows-x64.zip"
if ($version -eq "latest") {
  $url = "https://github.com/$repo/releases/latest/download/$asset"
} else {
  $tag = if ($version.StartsWith("v")) { $version } else { "v$version" }
  $url = "https://github.com/$repo/releases/download/$tag/$asset"
}

$tmp = Join-Path $env:TEMP ("hyperhub-install-" + [guid]::NewGuid().ToString("N"))
$zip = Join-Path $tmp $asset
$extract = Join-Path $tmp "extract"
New-Item -ItemType Directory -Force -Path $tmp, $extract, $installDir | Out-Null
try {
  Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
  Expand-Archive -Force -Path $zip -DestinationPath $extract
  $exe = Get-ChildItem -LiteralPath $extract -Recurse -Filter hyperhub.exe | Select-Object -First 1
  if (-not $exe) { throw "hyperhub.exe not found in $asset" }

  $target = Join-Path $installDir "hyperhub.exe"
  Copy-Item -Force -LiteralPath $exe.FullName -Destination $target
  $shortcut = Join-Path $installDir "hsh.cmd"
  $shortcutContent = @"
@echo off
"$target" run cmd %*
"@
  $shortcutContent | Set-Content -LiteralPath $shortcut -Encoding ascii
  $path = [Environment]::GetEnvironmentVariable("Path", "User")
  if (($path -split ";") -notcontains $installDir) {
    $newPath = if ([string]::IsNullOrWhiteSpace($path)) { $installDir } else { "$path;$installDir" }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    $env:Path = "$env:Path;$installDir"
    Write-Host "Added to user PATH: $installDir"
  }
  & $target --help | Out-Null
  Write-Host "hyperhub installed to $target"
  Write-Host "shortcut installed to $shortcut"
} finally {
  Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
}
