[CmdletBinding()]
param([string]$HyperHub, [string]$Output, [string]$PosixRuntimeCompiler)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This Suite requires Windows.' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $HyperHub) { $HyperHub = Join-Path $root 'target/release/hyperhub.exe' }
if (-not $Output) { $Output = Join-Path $root 'target/benchmarks/windows-hooks' }
Push-Location $root
$previousGumRoot = $env:HYPERHUB_FRIDA_GUM_ROOT
$previousEngineCli = $env:HYPERHUB_TEST_ENGINE_HYPERHUB
$previousEngineBackend = $env:HYPERHUB_TEST_ENGINE_BACKEND
$previousWorkerFixture = $env:HH_FORWARD_WORKER_FIXTURE
$previousReleaseCli = $env:HYPERHUB_TEST_RELEASE_HYPERHUB
$previousReleaseDiagnostics = $env:HYPERHUB_TEST_RELEASE_DIAGNOSTICS
$previousRestartCli = $env:HYPERHUB_TEST_RESTART_HYPERHUB
$previousAliasCli = $env:HYPERHUB_TEST_ALIAS_HYPERHUB
try {
  if (-not $env:HYPERHUB_FRIDA_GUM_ROOT) {
    $env:HYPERHUB_FRIDA_GUM_ROOT = Join-Path $root '.deps/frida-gum/17.17.0/windows-x64'
  }
  New-Item -ItemType Directory -Path $Output -Force | Out-Null
  $env:HYPERHUB_TEST_RELEASE_HYPERHUB = $HyperHub
  $env:HYPERHUB_TEST_RELEASE_DIAGNOSTICS = Join-Path $Output 'release-diagnostics'
  # Run the complete joint fixture first for fast failure diagnostics. Success
  # still requires every existing Agent/Host/worker/recovery/Hook Suite below.
  cargo test --locked -p hyperhub --test release_live -- --ignored --nocapture
  if ($LASTEXITCODE -ne 0) { throw 'Windows joint release and installation upgrade failed.' }
  cargo test --locked -p hyperhub-runtime attachment::transport::tests -- --nocapture
  if ($LASTEXITCODE -ne 0) { throw 'Windows authenticated attachment pipe concurrency regression failed.' }
  cargo test --locked --release -p hyperhub-agent-core --features gum-agent
  if ($LASTEXITCODE -ne 0) { throw 'Windows Gum Agent tests failed.' }
  $env:HYPERHUB_TEST_ENGINE_HYPERHUB = $HyperHub
  $env:HYPERHUB_TEST_ENGINE_BACKEND = 'gum'
  # Keep the already-built embedded release CLI intact while compiling the test.
  cargo test --locked -p hyperhub --test engine_host_live -- --ignored --nocapture
  if ($LASTEXITCODE -ne 0) { throw 'Windows native Host live upgrade failed.' }
  $env:HYPERHUB_TEST_RESTART_HYPERHUB = $HyperHub
  cargo test --locked -p hyperhub --test serve_restart_live -- --ignored --nocapture --test-threads=1
  if ($LASTEXITCODE -ne 0) { throw 'Windows Serve restart lost an executor or its protection.' }
  cargo test --locked -p hyperhub --test executor_scope_live -- --ignored --nocapture
  if ($LASTEXITCODE -ne 0) { throw 'Windows external IPC executor scope regression failed.' }
  $env:HYPERHUB_TEST_ALIAS_HYPERHUB = $HyperHub
  cargo test --locked -p hyperhub --test file_alias_live -- --ignored --nocapture --test-threads=1
  if ($LASTEXITCODE -ne 0) { throw 'Windows file namespace alias regression failed.' }
  $env:HH_FORWARD_WORKER_FIXTURE = $HyperHub
  cargo test --locked -p hyperhub-core --test forward_workers -- --ignored --nocapture
  if ($LASTEXITCODE -ne 0) { throw 'Windows forwarding worker upgrade failed.' }
  cargo test --locked -p hyperhub-core --lib durable_release_recovery_status_installation_and_missing_host_boundaries -- --ignored --nocapture
  if ($LASTEXITCODE -ne 0) { throw 'Windows release recovery state tests failed.' }
  cargo run --release --locked -p hyperhub-engine --example native_upgrade_bench -- (Join-Path $Output 'native-engine-performance')
  if ($LASTEXITCODE -ne 0) { throw 'Windows native Engine switch benchmark failed.' }
  cargo build --locked --release -p hyperhub-agent-core --example windows_hook_probe
  if ($LASTEXITCODE -ne 0) { throw 'Windows regression fixture build failed.' }
  python (Join-Path $root 'tests/benchmarks/windows-hooks/run.py') `
    --hyperhub $HyperHub --probe (Join-Path $root 'target/release/examples/windows_hook_probe.exe') `
    --output $Output
  if ($LASTEXITCODE -ne 0) { throw 'Windows Hook regression Suite failed.' }
  cargo build --locked --release -p hyperhub-runtime --example attachment_init_failure
  if ($LASTEXITCODE -ne 0) { throw 'Windows native initialization failure fixture build failed.' }
  python (Join-Path $root 'tests/test_dynamic_attach_windows_env.py')
  if ($LASTEXITCODE -ne 0) { throw 'Windows disposable fixture environment isolation failed.' }
  cargo build --locked --manifest-path tests/fixtures/dynamic-attach-terminal/Cargo.toml --target-dir target/terminal-fixture
  if ($LASTEXITCODE -ne 0) { throw 'Windows target terminal fixture build failed.' }
  $terminalFixture = Join-Path $root 'target/terminal-fixture/debug/dynamic-attach-terminal.exe'
  python (Join-Path $root 'scripts/test-dynamic-attach-terminal.py') --fixture $terminalFixture --native-only --output (Join-Path $Output 'target-terminal-native')
  if ($LASTEXITCODE -ne 0) { throw 'Windows target ConPTY native baseline failed.' }
  foreach ($terminalOrigin in @('attach', 'run')) {
    python (Join-Path $root 'scripts/test-dynamic-attach-terminal.py') --fixture $terminalFixture --hyperhub $HyperHub --backend gum --origin $terminalOrigin --cycles 2 --output (Join-Path $Output "target-terminal-$terminalOrigin")
    if ($LASTEXITCODE -ne 0) { throw "Windows target ConPTY $terminalOrigin transparency failed." }
  }
  python (Join-Path $root 'scripts/test-dynamic-attach-windows.py') `
    --hyperhub $HyperHub --backend gum --cycles 3 --duration 0 --init-failure-probe (Join-Path $root 'target/release/examples/attachment_init_failure.exe') `
    --output (Join-Path $Output 'dynamic-attachment')
  if ($LASTEXITCODE -ne 0) { throw 'Windows dynamic attachment and ConPTY approval regression failed.' }
  python (Join-Path $root 'scripts/test-dynamic-attach-windows.py') `
    --hyperhub $HyperHub --backend gum --origin run --cycles 3 --duration 0 --init-failure-probe (Join-Path $root 'target/release/examples/attachment_init_failure.exe') `
    --output (Join-Path $Output 'dynamic-owned-run')
  if ($LASTEXITCODE -ne 0) { throw 'Windows reversible owned run and surviving descendant regression failed.' }
  if ($PosixRuntimeCompiler) {
    python (Join-Path $root 'scripts/test-dynamic-attach-posix-runtime.py') `
      --compiler $PosixRuntimeCompiler --native-only --output (Join-Path $Output 'posix-runtime-native')
    if ($LASTEXITCODE -ne 0) { throw 'Windows POSIX-runtime fork native oracle failed.' }
    python (Join-Path $root 'scripts/test-dynamic-attach-posix-runtime.py') `
      --compiler $PosixRuntimeCompiler --hyperhub $HyperHub --expect-unsupported --output (Join-Path $Output 'posix-runtime-capability-refusal')
    if ($LASTEXITCODE -ne 0) { throw 'Windows POSIX-runtime pre-mutation capability refusal failed.' }
  }
  else {
    @{ schema_version = 1; status = 'not_executed'; feature = 'posix_runtime_fork';
       reason = 'Provide -PosixRuntimeCompiler with a real MSYS/Cygwin gcc.exe; native MinGW is not an equivalent oracle.' } |
      ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Output 'posix-runtime-not-executed.json') -Encoding utf8
  }
}
finally {
  $env:HYPERHUB_FRIDA_GUM_ROOT = $previousGumRoot
  $env:HYPERHUB_TEST_ENGINE_HYPERHUB = $previousEngineCli
  $env:HYPERHUB_TEST_ENGINE_BACKEND = $previousEngineBackend
  $env:HH_FORWARD_WORKER_FIXTURE = $previousWorkerFixture
  $env:HYPERHUB_TEST_RELEASE_HYPERHUB = $previousReleaseCli
  $env:HYPERHUB_TEST_RELEASE_DIAGNOSTICS = $previousReleaseDiagnostics
  $env:HYPERHUB_TEST_RESTART_HYPERHUB = $previousRestartCli
  $env:HYPERHUB_TEST_ALIAS_HYPERHUB = $previousAliasCli
  Pop-Location
}
