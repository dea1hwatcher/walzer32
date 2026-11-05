<#
.SYNOPSIS
    Automated build & packaging script for Walzer32 Android Container APK.
.DESCRIPTION
    1. Cross-compiles `walzer32-android` (libwalzer32.so) for target `aarch64-linux-android`.
    2. Packages `libwalzer32.so` into `android/app/src/main/jniLibs/arm64-v8a/`.
    3. Invokes Gradle to produce the final `Walzer32Loader.apk`.
#>

[CmdletBinding()]
param(
    [string]$Target = "aarch64-linux-android",
    [string]$Profile = "release-android",
    [switch]$SkipApk = $false
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$JniLibsDir = Join-Path $RootDir "android\app\src\main\jniLibs\arm64-v8a"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Walzer32 Android Automated Build & Packaging Pipeline" -ForegroundColor Cyan
Write-Host " Target:  $Target" -ForegroundColor Gray
Write-Host " Profile: $Profile" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Rust target
Write-Host "`n[1/4] Checking Rust cross-compilation target..." -ForegroundColor Yellow
$installedTargets = rustup target list --installed
if (-not ($installedTargets -match $Target)) {
    Write-Host "Target '$Target' not installed. Installing via rustup..." -ForegroundColor Yellow
    rustup target add $Target
}

# 2. Build libwalzer32.so cdylib
Write-Host "`n[2/4] Compiling walzer32-android cdylib ($Target)..." -ForegroundColor Yellow
Push-Location $RootDir
try {
    $cargoCmd = "cargo build -p walzer32-android --profile $Profile --target $Target"
    Write-Host "Running: $cargoCmd" -ForegroundColor Gray
    Invoke-Expression $cargoCmd
} finally {
    Pop-Location
}

# 3. Locate and copy libwalzer32.so into jniLibs
Write-Host "`n[3/4] Copying libwalzer32.so into Android container jniLibs..." -ForegroundColor Yellow
$candidates = @(
    (Join-Path $RootDir "target\$Target\$Profile\libwalzer32_android.so"),
    (Join-Path $RootDir "target\$Target\$Profile\libwalzer32.so"),
    (Join-Path $RootDir "target\$Target\release\libwalzer32_android.so"),
    (Join-Path $RootDir "target\$Target\release\libwalzer32.so")
)
$builtSoPath = $null
foreach ($c in $candidates) {
    if (Test-Path $c) {
        $builtSoPath = $c
        break
    }
}
if (-not $builtSoPath) {
    throw "Could not find compiled libwalzer32_android.so or libwalzer32.so at target\$Target\$Profile"
}

if (-not (Test-Path $JniLibsDir)) {
    New-Item -ItemType Directory -Path $JniLibsDir -Force | Out-Null
}

$destPath = Join-Path $JniLibsDir "libwalzer32.so"
Copy-Item -Path $builtSoPath -Destination $destPath -Force
$soSizeKb = [math]::Round((Get-Item $destPath).Length / 1024, 2)
Write-Host "Successfully packaged: $destPath ($soSizeKb KB)" -ForegroundColor Green

# 4. Build Android APK via Gradle
if (-not $SkipApk) {
    Write-Host "`n[4/4] Building Walzer32 Android APK via Gradle..." -ForegroundColor Yellow
    $AndroidDir = Join-Path $RootDir "android"
    Push-Location $AndroidDir
    try {
        if (Test-Path ".\gradlew.bat") {
            .\gradlew.bat assembleDebug
            Write-Host "`n[SUCCESS] Walzer32Loader APK successfully built!" -ForegroundColor Green
            Write-Host "APK Location: android\app\build\outputs\apk\debug\app-debug.apk" -ForegroundColor Green
        } elseif (Get-Command "gradle" -ErrorAction SilentlyContinue) {
            gradle assembleDebug
            Write-Host "`n[SUCCESS] Walzer32Loader APK successfully built!" -ForegroundColor Green
        } else {
            Write-Host "Gradle wrapper not initialized yet. Run 'gradle wrapper' in android/ or open project in Android Studio." -ForegroundColor DarkYellow
        }
    } finally {
        Pop-Location
    }
}

Write-Host "`n=== Pipeline Complete ===" -ForegroundColor Cyan
