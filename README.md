# Mock Android Match SDK

## Overview
The `mock-android-match-sdk` repository provides an Android library implementation of `IBioApiV2` to perform 1:1 and 1:N match, extraction, quality check, and format conversion of biometric data. It simulates biometric SDK behavior on-device and is designed for testing and integration within Android-based MOSIP android registration client applications.

## Features
- **Biometric Operations**: Simulates 1:1 and 1:N matching, extraction, and quality checks.
- **Format Conversion**: Converts biometric data from ISO 19794-4 (Finger), ISO 19794-5 (Face), and ISO 19794-6 (Iris) containers to JPEG or PNG images using [`bio-utils`](https://github.com/mosip/bio-utils).
- **Standard Compliance**: Implements the `IBioApiV2` interface as per MOSIP [`kernel-biometrics-api`](https://github.com/mosip/commons/tree/master/kernel/kernel-biometrics-api) specifications.
- **AAR Packaging**: Built and published as an Android library (AAR) for direct consumption via Gradle/Maven.

## Modules
- **matchsdk**: The library module (`io.mosip.mock.sdk`). Main implementation class is `SampleSDK` (`io.mosip.mock.sdk.impl.SampleSDK`), which implements `IBioApiV2` and delegates to:
    - `MatchService` — 1:1 and 1:N match decisions (compares biometric byte objects)
    - `CheckQualityService` — quality scoring
    - `ExtractTemplateService` — template extraction
    - `ConvertFormatService` / `ConverterServiceImpl` — format conversion
    - `SDKInfoService` — SDK metadata/version info
- **app**: A minimal sample Android application module used as a shell for manually exercising the library.

## Local Setup
Since `matchsdk` is a library, setting it up involves building it and including it as a dependency in your Android project.

### Prerequisites
Ensure you have the following installed before proceeding:
- **Android Studio**: Latest stable version.
- **JDK**: 11
- **Gradle**: Wrapper included (`./gradlew`), no separate install required.
- **Git**: To clone the repository.

### Running the Application
`matchsdk` is consumed as a local AAR dependency by Android applications that need an on-device biometric SDK implementing `IBioApiV2`. Build the AAR locally (see below), add it to your project, and instantiate `SampleSDK` directly in your app.

## Build locally
To build the library locally:

1. Clone the repository:
   ```bash
   git clone https://github.com/mosip/mock-android-match-sdk.git
   cd mock-android-match-sdk
   ```

2. Build the project:
   ```bash
   ./gradlew build
   ```
   This compiles both modules.

3. Assemble the release AAR:
   ```bash
   ./gradlew :matchsdk:assembleRelease
   ```
   The AAR is generated at `matchsdk/build/outputs/aar/`.

## Documentation
Android Match SDK follows an implementation based on the MOSIP Biometric SDK specification (`IBioApiV2`).

## Contribution & Community
We welcome contributions from everyone!

Check [MOSIP's code contribution guidelines](https://docs.mosip.io/1.2.0/community/code-contributions) to learn how you can contribute code to this application.

If you have any questions or run into issues while trying out the application, feel free to post them in the [MOSIP Community](https://community.mosip.io/) — we'll be happy to help you out.

[GitHub Issues](https://github.com/mosip/mock-android-match-sdk/issues)

## License
This project is licensed under the terms of the MIT License. See the [LICENSE](LICENSE) file for full license details.