param([int]$Seconds = 60)
$ErrorActionPreference = 'Stop'
if ($Seconds -lt 1) { throw 'Seconds must be positive' }
$workspace = Split-Path -Parent $PSScriptRoot
$target = Join-Path $workspace 'target\coverage-fuzz'
$corpus = Join-Path $target 'corpus'
New-Item -ItemType Directory -Path $corpus -Force | Out-Null
$vcvars = Get-ChildItem 'C:/Program Files/Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvars64.bat' | Select-Object -First 1
if (-not $vcvars) { throw 'MSVC x64 tools required' }
$vc = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $vcvars.FullName))
$clang = Join-Path $vc 'Tools\Llvm\x64\bin\clang-cl.exe'
$fuzzer = Get-ChildItem (Join-Path $vc 'Tools\Llvm\x64\lib\clang\*\lib\windows\clang_rt.fuzzer-x86_64.lib') | Select-Object -First 1
if (-not (Test-Path -LiteralPath $clang) -or -not $fuzzer) { throw 'Clang libFuzzer runtime required' }
$manifest = Join-Path $workspace 'fuzz\Cargo.toml'
$oldFlags = $env:RUSTFLAGS
$oldTarget = $env:CARGO_TARGET_DIR
try {
    $env:CARGO_TARGET_DIR = Join-Path $target 'rust'
    cargo +nightly run --locked --offline --manifest-path $manifest --example seeds -- $corpus
    if ($LASTEXITCODE -ne 0) { throw 'Seed generation failed' }
    foreach ($name in @('native_cpp_fh3.exe', 'native_cpp_fh4.exe', 'native_cpp_guarded.exe', 'native_seh.exe')) {
        $fixture = Join-Path $workspace "target\native-fixtures\$name"
        if (Test-Path -LiteralPath $fixture) { Copy-Item -LiteralPath $fixture -Destination (Join-Path $corpus $name) -Force }
    }
    $env:RUSTFLAGS = '-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares'
    cargo +nightly build --locked --offline --manifest-path $manifest --release --lib --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Instrumented build failed' }
    $library = Join-Path $env:CARGO_TARGET_DIR 'x86_64-pc-windows-msvc\release\sigbraker_fuzz.lib'
    $exe = Join-Path $target 'sigbraker-fuzz.exe'
    $obj = Join-Path $target 'driver.obj'
    $driver = Join-Path $workspace 'fuzz\driver.cpp'
    $command = 'call "{0}" >nul && "{1}" /nologo /MD "{2}" /Fo:"{3}" /Fe:"{4}" /link "{5}" "{6}" advapi32.lib userenv.lib ws2_32.lib bcrypt.lib ntdll.lib kernel32.lib user32.lib synchronization.lib dbghelp.lib' -f $vcvars.FullName,$clang,$driver,$obj,$exe,$library,$fuzzer.FullName
    & $env:ComSpec /d /c $command
    if ($LASTEXITCODE -ne 0) { throw 'Fuzzer linking failed' }
    $log = Join-Path $target (('run-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) + '.log')
    & $exe "-max_total_time=$Seconds" '-timeout=10' '-rss_limit_mb=4096' '-max_len=2097152' '-print_final_stats=1' "-artifact_prefix=$target/" $corpus 2>&1 | Tee-Object -FilePath $log
    if ($LASTEXITCODE -ne 0) { throw "Coverage fuzzing failed; see $log" }
    Write-Output "FUZZ LOG $log"
} finally {
    $env:RUSTFLAGS = $oldFlags
    $env:CARGO_TARGET_DIR = $oldTarget
}
