#!/usr/bin/env bash
# Automated build & packaging script for Walzer32 Android Container APK.

set -euo pipefail

TARGET="${1:-aarch64-linux-android}"
PROFILE="${2:-release-android}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
JNI_LIBS_DIR="${ROOT_DIR}/android/app/src/main/jniLibs/arm64-v8a"

echo "=========================================================="
echo " Walzer32 Android Automated Build & Packaging Pipeline"
echo " Target:  ${TARGET}"
echo " Profile: ${PROFILE}"
echo "=========================================================="

# 1. Check Rust target
echo -e "\n[1/4] Checking Rust cross-compilation target..."
if ! rustup target list --installed | grep -q "${TARGET}"; then
    echo "Target '${TARGET}' not installed. Installing via rustup..."
    rustup target add "${TARGET}"
fi

# 2. Build libwalzer32.so cdylib
echo -e "\n[2/4] Compiling walzer32-android cdylib (${TARGET})..."
cd "${ROOT_DIR}"
cargo build -p walzer32-android --profile "${PROFILE}" --target "${TARGET}"

# 3. Copy libwalzer32.so into jniLibs
echo -e "\n[3/4] Copying libwalzer32.so into Android container jniLibs..."
BUILT_SO="${ROOT_DIR}/target/${TARGET}/${PROFILE}/libwalzer32.so"
if [[ ! -f "${BUILT_SO}" ]]; then
    BUILT_SO="${ROOT_DIR}/target/${TARGET}/release/libwalzer32.so"
fi

mkdir -p "${JNI_LIBS_DIR}"
cp -f "${BUILT_SO}" "${JNI_LIBS_DIR}/libwalzer32.so"
echo "Successfully packaged: ${JNI_LIBS_DIR}/libwalzer32.so"

# 4. Build APK
echo -e "\n[4/4] Building Walzer32 Android APK via Gradle..."
cd "${ROOT_DIR}/android"
if [[ -f "./gradlew" ]]; then
    ./gradlew assembleDebug
    echo -e "\n[SUCCESS] Walzer32Loader APK successfully built!"
elif command -v gradle &> /dev/null; then
    gradle assembleDebug
    echo -e "\n[SUCCESS] Walzer32Loader APK successfully built!"
else
    echo "Gradle wrapper not initialized yet. Open project in Android Studio or run gradle wrapper."
fi

echo -e "\n=== Pipeline Complete ==="
