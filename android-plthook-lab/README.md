# Android PLT hook lab

This folder is an isolated Android test area. Do not edit the upstream
`plthook` checkout from here; copy or reimplement only the small experiments
you want to test.

## Layout

- `jni/Android.mk` and `jni/Application.mk`: NDK build configuration.
- `jni/claimcheck.c`: executable test entry point.
- `jni/libtarget.c`: small shared library used by the executable.
- `scripts/build.sh`: builds the native binaries with `ndk-build`.
- `scripts/run_on_device.sh`: pushes and runs the test on an emulator/device.

## Local usage

```sh
cd android-plthook-lab
./scripts/build.sh
./scripts/run_on_device.sh
```

The run script expects `adb` to see one booted Android device or emulator.

