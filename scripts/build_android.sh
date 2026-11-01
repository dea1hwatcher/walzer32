#!/usr/bin/env bash
# Automated build & packaging script for Transd Android Container APK.

set -euo pipefail

TARGET="${1:-aarch64-linux-android}"
PROFILE="${2:-release-android}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
JNI_LIBS_DIR="${ROOT_DIR}/android/app/src/main/jniLibs/arm64-v8a"

echo "=========================================================="
echo " Transd Android Automated Build & Packaging Pipeline"
echo " Target:  ${TARGET}"
echo " Profile: ${PROFILE}"
echo "=========================================================="

# 1. Check Rust target
echo -e "\n[1/4] Checking Rust cross-compilation target..."
if ! rustup target list --installed | grep -q "${TARGET}"; then
    echo "Target '${TARGET}' not installed. Installing via rustup..."
    rustup target add "${TARGET}"
fi

# 2. Build libtransd.so cdylib
echo -e "\n[2/4] Compiling transd-android cdylib (${TARGET})..."
cd "${ROOT_DIR}"
cargo build -p transd-android --profile "${PROFILE}" --target "${TARGET}"

# 3. Copy libtransd.so into jniLibs
echo -e "\n[3/4] Copying libtransd.so into Android container jniLibs..."
BUILT_SO="${ROOT_DIR}/target/${TARGET}/${PROFILE}/libtransd.so"
if [[ ! -f "${BUILT_SO}" ]]; then
    BUILT_SO="${ROOT_DIR}/target/${TARGET}/release/libtransd.so"
fi

mkdir -p "${JNI_LIBS_DIR}"
cp -f "${BUILT_SO}" "${JNI_LIBS_DIR}/libtransd.so"
echo "Successfully packaged: ${JNI_LIBS_DIR}/libtransd.so"

# 4. Build APK
echo -e "\n[4/4] Building Transd Android APK via Gradle..."
cd "${ROOT_DIR}/android"
if [[ -f "./gradlew" ]]; then
    ./gradlew assembleDebug
    echo -e "\n[SUCCESS] TransdLoader APK successfully built!"
elif command -v gradle &> /dev/null; then
    gradle assembleDebug
    echo -e "\n[SUCCESS] TransdLoader APK successfully built!"
else
    echo "Gradle wrapper not initialized yet. Open project in Android Studio or run gradle wrapper."
fi

echo -e "\n=== Pipeline Complete ==="
