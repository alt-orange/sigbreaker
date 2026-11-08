$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$output = Join-Path $workspace 'target\native-fixtures'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$installations = @("${env:ProgramFiles}\Microsoft Visual Studio", "${env:ProgramFiles(x86)}\Microsoft Visual Studio")
$vcvars = $installations | ForEach-Object {
    Get-ChildItem -Path "$_\*\*\VC\Auxiliary\Build\vcvars64.bat" -ErrorAction SilentlyContinue
} | Select-Object -First 1
if (-not $vcvars) { throw 'MSVC x64 build tools were not found' }
$source = Join-Path $workspace 'tests\fixtures\native_cpp.cpp'
$exe = Join-Path $output 'native_cpp.exe'
$obj = Join-Path $output 'native_cpp.obj'
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /O2 /EHsc /MT /guard:cf "{1}" /Fo:"{2}" /Fe:"{3}" /link /INCREMENTAL:NO /MAP:"{3}.map"' -f $vcvars.FullName, $source, $obj, $exe
& $env:ComSpec /d /c $command
if ($LASTEXITCODE -ne 0) { throw 'C++ fixture compilation failed' }
Write-Output $exe
$dll = Join-Path $output 'native_cpp.dll'
$dllObj = Join-Path $output 'native_dll.obj'
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /O2 /EHsc /MT /guard:cf /LD /DNATIVE_DLL "{1}" /Fo:"{2}" /Fe:"{3}" /link /INCREMENTAL:NO /MAP:"{3}.map"' -f $vcvars.FullName, $source, $dllObj, $dll
& $env:ComSpec /d /c $command
if ($LASTEXITCODE -ne 0) { throw 'DLL fixture compilation failed' }
Write-Output $dll
$seh = Join-Path $workspace 'tests\fixtures\native_seh.c'
$sehExe = Join-Path $output 'native_seh.exe'
$sehObj = Join-Path $output 'native_seh.obj'
$chain = Join-Path $workspace 'tests\fixtures\native_chain.asm'
$chainObj = Join-Path $output 'native_chain.obj'
$command = 'call "{0}" >nul && ml64 /nologo /c /Fo"{1}" "{2}" && cl /nologo /O2 /MD /GS- /guard:cf "{3}" "{1}" /Fo:"{4}" /Fe:"{5}" /link /INCREMENTAL:NO /EXPORT:chained_probe /EXPORT:chained_body /EXPORT:tail_probe' -f $vcvars.FullName, $chainObj, $chain, $seh, $sehObj, $sehExe
& $env:ComSpec /d /c $command
if ($LASTEXITCODE -ne 0) { throw 'SEH fixture compilation failed' }
Write-Output $sehExe

foreach ($variant in @('fh3', 'fh4', 'guarded')) {
    $variantExe = Join-Path $output "native_cpp_$variant.exe"
    $variantObj = Join-Path $output "native_cpp_$variant.obj"
    $compilerFlags = if ($variant -eq 'fh3') { '/d2FH4-' } elseif ($variant -eq 'guarded') { '/guard:ehcont' } else { '' }
    $linkerFlags = if ($variant -eq 'guarded') { '/guard:ehcont /CETCOMPAT' } else { '' }
    $command = 'call "{0}" >nul && cl /nologo /std:c++17 /O2 /EHsc /MD /GS- {4} "{1}" /Fo:"{2}" /Fe:"{3}" /link /INCREMENTAL:NO /MAP:"{3}.map" {5}' -f $vcvars.FullName, $source, $variantObj, $variantExe, $compilerFlags, $linkerFlags
    & $env:ComSpec /d /c $command
    if ($LASTEXITCODE -ne 0) { throw "C++ $variant fixture compilation failed" }
}
$clang = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $vcvars.FullName))) 'Tools\Llvm\x64\bin\clang-cl.exe'
if (Test-Path -LiteralPath $clang) {
    $variantExe = Join-Path $output 'native_cpp_clang.exe'
    $variantObj = Join-Path $output 'native_cpp_clang.obj'
    $command = 'call "{0}" >nul && "{4}" /nologo /std:c++17 /O2 /EHsc /MD /GS- "{1}" /Fo:"{2}" /Fe:"{3}" /link /INCREMENTAL:NO /MAP:"{3}.map"' -f $vcvars.FullName, $source, $variantObj, $variantExe, $clang
    & $env:ComSpec /d /c $command
    if ($LASTEXITCODE -ne 0) { throw 'Clang fixture compilation failed' }
}
