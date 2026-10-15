[CmdletBinding()]
param([string]$HyperHub, [string]$Output)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This Suite requires Windows.' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $HyperHub) { $HyperHub = Join-Path $root 'target/release/hyperhub.exe' }
if (-not $Output) { $Output = Join-Path $root 'target/benchmarks/windows-hooks' }
Push-Location $root
$previousGumRoot = $env:HYPERHUB_FRIDA_GUM_ROOT
try {
  if (-not $env:HYPERHUB_FRIDA_GUM_ROOT) {
    $env:HYPERHUB_FRIDA_GUM_ROOT = Join-Path $root '.deps/frida-gum/17.17.0/windows-x64'
  }
  cargo test --locked --release -p hyperhub-agent-core --features gum-agent
  if ($LASTEXITCODE -ne 0) { throw 'Windows Gum Agent tests failed.' }
  cargo build --locked --release -p hyperhub-agent-core --example windows_hook_probe
  if ($LASTEXITCODE -ne 0) { throw 'Windows regression fixture build failed.' }
  python (Join-Path $root 'tests/benchmarks/windows-hooks/run.py') `
    --hyperhub $HyperHub --probe (Join-Path $root 'target/release/examples/windows_hook_probe.exe') `
    --output $Output
  if ($LASTEXITCODE -ne 0) { throw 'Windows Hook regression Suite failed.' }
}
finally {
  $env:HYPERHUB_FRIDA_GUM_ROOT = $previousGumRoot
  Pop-Location
}
