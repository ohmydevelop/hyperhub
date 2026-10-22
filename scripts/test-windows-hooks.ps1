[CmdletBinding()]
param([string]$HyperHub, [string]$Output)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This Suite requires Windows.' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $HyperHub) { $HyperHub = Join-Path $root 'target/release/hyperhub.exe' }
if (-not $Output) { $Output = Join-Path $root 'target/benchmarks/windows-hooks' }
Push-Location $root
$previousGumRoot = $env:HYPERHUB_FRIDA_GUM_ROOT
$previousEngineCli = $env:HYPERHUB_TEST_ENGINE_HYPERHUB
$previousEngineBackend = $env:HYPERHUB_TEST_ENGINE_BACKEND
try {
  if (-not $env:HYPERHUB_FRIDA_GUM_ROOT) {
    $env:HYPERHUB_FRIDA_GUM_ROOT = Join-Path $root '.deps/frida-gum/17.17.0/windows-x64'
  }
  cargo test --locked --release -p hyperhub-agent-core --features gum-agent
  if ($LASTEXITCODE -ne 0) { throw 'Windows Gum Agent tests failed.' }
  $env:HYPERHUB_TEST_ENGINE_HYPERHUB = $HyperHub
  $env:HYPERHUB_TEST_ENGINE_BACKEND = 'gum'
  # Keep the already-built embedded release CLI intact while compiling the test.
  cargo test --locked -p hyperhub --test engine_host_live -- --ignored --nocapture
  if ($LASTEXITCODE -ne 0) { throw 'Windows native Host live upgrade failed.' }
  cargo build --locked --release -p hyperhub-agent-core --example windows_hook_probe
  if ($LASTEXITCODE -ne 0) { throw 'Windows regression fixture build failed.' }
  python (Join-Path $root 'tests/benchmarks/windows-hooks/run.py') `
    --hyperhub $HyperHub --probe (Join-Path $root 'target/release/examples/windows_hook_probe.exe') `
    --output $Output
  if ($LASTEXITCODE -ne 0) { throw 'Windows Hook regression Suite failed.' }
}
finally {
  $env:HYPERHUB_FRIDA_GUM_ROOT = $previousGumRoot
  $env:HYPERHUB_TEST_ENGINE_HYPERHUB = $previousEngineCli
  $env:HYPERHUB_TEST_ENGINE_BACKEND = $previousEngineBackend
  Pop-Location
}
