# AGENTS.md

## Repository Overview

`mock-android-match-sdk` is an Android library that implements the MOSIP
`IBioApiV2` interface (from `kernel-biometrics-api`) to simulate biometric
SDK behavior: 1:1 and 1:N match, quality check, template extraction, and
format conversion (ISO 19794-4/5/6 to JPEG/PNG).

This is a **mock / test-double**, not a production biometric matcher. It is
meant to stand in for a real SBI (Standard Biometric Interface) matching
algorithm during development and testing of Android-based MOSIP
registration client apps, so those apps can be built and exercised without
a real, licensed biometric SDK on hand. Do not treat any matching/quality
logic here as representative of real biometric accuracy — it is a
deterministic or trivial stand-in for wiring and integration testing.

The repository has two Gradle modules:

- `matchsdk` — the actual library module (namespace `io.mosip.mock.sdk`).
  Main entry point is `SampleSDK`
  (`matchsdk/src/main/java/io/mosip/mock/sdk/impl/SampleSDK.java`), which
  implements `IBioApiV2` and delegates to:
  - `MatchService` — 1:1 / 1:N match decisions
  - `CheckQualityService` — quality scoring
  - `ExtractTemplateService` — template extraction
  - `ConvertFormatService` / `ConverterServiceImpl` — format conversion
  - `SDKInfoService` — SDK metadata/version info
- `app` — a minimal, mostly-boilerplate sample Android application used as
  a shell for manually exercising the library. It is not a real product;
  do not assume it demonstrates a full integration.

## Technology Stack

- Language: Java (source/target compatibility 1.8 in both modules)
- Build: Gradle, via the wrapper (`./gradlew` / `gradlew.bat`) — no local
  Gradle install required
- Android Gradle Plugin: 7.2.0 (`com.android.application`,
  `com.android.library`), declared in the root `build.gradle`
- `compileSdk 31`, `minSdk 28` in both modules
- Dependency injection: Dagger 2.41 (in `matchsdk`)
- Test: JUnit 4.13.2 (unit), androidx.test / Espresso (instrumented)
- Coverage: JaCoCo, wired up as the `jacocoUnitTestReport` task in
  `matchsdk/build.gradle`
- MOSIP dependencies pulled from Maven coordinates in
  `matchsdk/build.gradle`: `kernel-core`, `biometrics-util`,
  `kernel-biometrics-api`, `kernel-cbeffutil-api` (all pinned to specific
  `1.2.0.x` versions there — check that file for the exact versions in use,
  they may have moved on since this was written)
- CI: GitHub Actions, JDK 17 (Temurin) — see `.github/workflows/build.yml`

## Build & Test Commands

All commands run from the repository root.

Build both modules:

```bash
./gradlew build
```

Assemble the release AAR for the library only (this is what CI does):

```bash
./gradlew :matchsdk:assembleRelease
```

The AAR is written to `matchsdk/build/outputs/aar/matchsdk-release.aar`.

Run unit tests for the library module:

```bash
./gradlew :matchsdk:test
```

Generate the JaCoCo coverage report (runs `testDebugUnitTest` first):

```bash
./gradlew :matchsdk:jacocoUnitTestReport
```

Reports land under `matchsdk/build/reports/`.

On Windows, use `gradlew.bat` in place of `./gradlew`.

There is no separate lint/checkstyle Gradle task defined in this repo as of
this writing — verify with `./gradlew tasks` before assuming one exists.

## Configuration

- `local.properties` (Android SDK path, etc.) is git-ignored at the repo
  root — never commit it. It is not present in the tracked tree; Android
  Studio / the SDK manager creates it automatically on first sync.
- No `.env` files, API keys, or secrets are used anywhere in this repo — it
  is a self-contained mock library with no external service calls.
- `matchsdk/build.gradle` has a commented-out `maven-publish` block for
  publishing the AAR as `io.mosip.registration.matchsdk:matchsdk:1.0`. It
  is currently inactive; do not assume artifacts are published from this
  repo unless that block (or an equivalent CI publish step) is enabled.

## Project Structure Notes

```text
mock-android-match-sdk/
  app/                  sample shell app (not a real product)
  matchsdk/             the library module — this is the actual deliverable
    src/main/java/io/mosip/mock/sdk/
      constant/         error codes, parameter/format/status enums
      exception/        ConversionException, SDKException
      impl/             SampleSDK (the IBioApiV2 implementation)
      service/          match, quality, extraction, conversion, info services
      service/impl/     ConverterServiceImpl
      util/             Util helper class
    src/test/           JUnit unit tests + XML fixture files under
                         src/test/resources/sample_files/
    src/androidTest/    instrumented tests (device/emulator required)
  build.gradle           root Gradle config (AGP plugin versions only)
  settings.gradle         module includes (`app`, `matchsdk`)
  .github/workflows/     build.yml (CI build/artifact only — does not run tests), use-pr-linker.yml
                         (auto-links PRs to issues, mosip/kattu action)
```

The repo is small and flat — there is no need for per-module AGENTS.md
files. This root file is the single source of guidance.

## Development Workflow

1. Fork and clone the repository.
2. Branch from `develop` (the active integration branch — both `master`
   and `develop`, plus `release*`, trigger CI per `build.yml`, but PRs
   should target `develop` unless told otherwise).
3. Make changes, keeping `matchsdk` self-contained — it should not depend
   on anything in `app`.
4. Run `./gradlew :matchsdk:test` locally before opening a PR.
5. If you touch match/quality/conversion logic, update or add unit tests
   under `matchsdk/src/test/java/io/mosip/mock/sdk/` — this module already
   has decent test coverage (`MatchSDKTest`, `SDKServiceTest`,
   `SampleSDKTest`, `ServiceCoverageTest`, `UtilTest`) plus XML fixtures in
   `src/test/resources/sample_files/`; follow that pattern for new fixtures.
6. Push to your fork and open a PR against `mosip/mock-android-match-sdk`.

## Pull Request Guidelines

- Target the `develop` branch.
- CI (`.github/workflows/build.yml`) runs `./gradlew :matchsdk:assembleRelease`
  on push and PR to `master`, `develop`, and `release*` branches — make sure
  the library still builds and assembles cleanly.
- A separate workflow (`use-pr-linker.yml`) auto-links PRs to GitHub issues
  via the shared `mosip/kattu` action; reference the tracking issue number
  in the PR description so that linkage works.
- Follow MOSIP's general contribution guidelines:
  <https://docs.mosip.io/1.2.0/community/code-contributions>
- Sign off commits (`git commit -s`) per standard MOSIP/DCO practice.

## Repository-Specific Considerations

- This is mock/test tooling. Resist the urge to "improve" the matching
  algorithm to be more realistic — its job is to be predictable for
  integration testing, not accurate. If a change to match/quality
  thresholds is genuinely needed, call that out explicitly in the PR
  description so reviewers know it's an intentional behavior change to the
  mock, not a bug fix.
- `matchsdk` implements a versioned external interface (`IBioApiV2` from
  `kernel-biometrics-api`). Changing method signatures on `SampleSDK` or
  the service interfaces under `matchsdk/src/main/java/io/mosip/mock/sdk/service/`
  can break consumers (e.g. `android-registration-client`) that depend on
  this AAR. Treat public API changes as breaking changes.
- The `app` module exists only to manually exercise the library; it is not
  a substitute for unit tests and is not published anywhere.
- Neither unit tests (`src/test/`) nor instrumented tests
  (`src/androidTest/`) are run by the current CI workflow
  (`.github/workflows/build.yml` only runs `:matchsdk:assembleRelease`
  and uploads the AAR). Run `./gradlew :matchsdk:test` locally before
  opening a PR. Instrumented tests additionally require a device or
  emulator — treat both as developer-local checks, not a CI gate.

## Agent rules

### Do

1. Treat `matchsdk` as the actual product; treat `app` as a manual test
   harness only.
2. Run `./gradlew :matchsdk:test` (and `:matchsdk:assembleRelease` if you
   touched build config) before proposing a change as complete.
3. Add or update unit tests and, where relevant, the XML fixtures under
   `matchsdk/src/test/resources/sample_files/` for any change to match,
   quality, extraction, or conversion logic.
4. Keep the mock's behavior simple and predictable — this SDK exists to
   unblock integration testing, not to model real biometric accuracy.
5. Call out any change to `IBioApiV2`-facing method signatures as a
   breaking change in the PR description.
6. Target the `develop` branch for PRs and reference the tracking issue so
   the PR-linker workflow can pick it up.

### Do not

1. Do not commit `local.properties`, build output (`build/`), or any
   `.idea`/`.gradle` local state — they are already git-ignored; do not
   force-add them.
2. Do not assume the `maven-publish` block in `matchsdk/build.gradle` is
   active — it is currently commented out.
3. Do not add real credentials, API keys, or network calls to this
   library — it is meant to run fully offline as a mock.
4. Do not rely on `src/androidTest/` (instrumented tests) as a CI gate —
   `build.yml` only runs the Gradle build/assemble task, not an
   emulator-backed test run.
5. Do not restructure `matchsdk`/`app` into per-module AGENTS.md files —
   the repo is small enough that this single root file is sufficient;
   keep guidance here unless the repo grows substantially.
