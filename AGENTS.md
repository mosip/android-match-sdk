# AGENTS.md

## Repository Overview

`mock-android-match-sdk` is an Android library implementing MOSIP's
`IBioApiV2` (from `kernel-biometrics-api`): 1:1/1:N match, quality check,
template extraction, ISO 19794-4/5/6 → JPEG/PNG conversion.

**This is a mock/test-double, not a production biometric matcher.** It
stands in for a real on-device SDK so `android-registration-client` can be
built/exercised without a licensed biometric SDK. Match/quality logic is a
deterministic stand-in for wiring tests — not representative of real
biometric accuracy.

Two Gradle modules:

- `matchsdk` — the actual library (namespace `io.mosip.mock.sdk`). Entry
  point `SampleSDK` (`matchsdk/src/main/java/io/mosip/mock/sdk/impl/`)
  implements `IBioApiV2`, delegating to `MatchService`,
  `CheckQualityService`, `ExtractTemplateService`,
  `ConvertFormatService`/`ConverterServiceImpl`, `SDKInfoService`.
- `app` — minimal sample shell app for manual exercising only; not a real
  product, not published.

## Technology Stack

- Java (source/target 1.8, both modules); Gradle via wrapper
  (`./gradlew`/`gradlew.bat`)
- AGP 7.2.0; `compileSdk 31`, `minSdk 28` (both modules)
- DI: Dagger 2.41 (`matchsdk`); Test: JUnit 4.13.2 (unit), androidx.test/
  Espresso (instrumented); Coverage: JaCoCo (`jacocoUnitTestReport` task)
- MOSIP deps in `matchsdk/build.gradle`: `kernel-core`, `biometrics-util`,
  `kernel-biometrics-api`, `kernel-cbeffutil-api` (pinned `1.2.0.x` — check
  the file for current versions)
- CI: GitHub Actions, JDK 17 Temurin (`.github/workflows/build.yml`)

## Build & Test Commands

Run from repo root; use `gradlew.bat` on Windows.

```bash
./gradlew build                          # both modules
./gradlew :matchsdk:assembleRelease      # library only — what CI does
./gradlew :matchsdk:test                 # unit tests
./gradlew :matchsdk:jacocoUnitTestReport # coverage (runs testDebugUnitTest first)
```

AAR output: `matchsdk/build/outputs/aar/matchsdk-release.aar`. Coverage
reports: `matchsdk/build/reports/`. No lint/checkstyle task exists as of
writing — check `./gradlew tasks` before assuming one.

## Configuration

- `local.properties` (Android SDK path) is git-ignored, not in the tracked
  tree — never commit it.
- No `.env`/API keys/secrets anywhere — fully offline mock, no external
  calls.
- `matchsdk/build.gradle` has a commented-out `maven-publish` block
  (`io.mosip.registration.matchsdk:matchsdk:1.0`) — inactive; don't assume
  artifacts publish from this repo.

## Project Structure Notes

```text
mock-android-match-sdk/
  app/                  sample shell app (not a real product)
  matchsdk/             the library — the actual deliverable
    src/main/java/io/mosip/mock/sdk/
      constant/         error codes, parameter/format/status enums
      exception/        ConversionException, SDKException
      impl/             SampleSDK (IBioApiV2 implementation)
      service/          match, quality, extraction, conversion, info
      service/impl/     ConverterServiceImpl
      util/             Util helper
    src/test/           JUnit tests + fixtures under resources/sample_files/
    src/androidTest/    instrumented tests (device/emulator required)
  build.gradle           root config (AGP plugin versions only)
  settings.gradle         module includes (app, matchsdk)
  .github/workflows/     build.yml (build/artifact only, no tests),
                         use-pr-linker.yml (mosip/kattu PR-issue linking)
```

Repo is small and flat — this root file is the only AGENTS.md needed.

## Development Workflow

1. Fork, clone, branch from `develop` (also: `master`/`release*` trigger
   CI; PRs target `develop` unless told otherwise).
2. Keep `matchsdk` self-contained — no dependency on `app`.
3. Run `./gradlew :matchsdk:test` locally before opening a PR (**CI does
   not run tests** — `build.yml` only runs `:matchsdk:assembleRelease`).
4. Changing match/quality/conversion logic → add/update unit tests under
   `matchsdk/src/test/java/io/mosip/mock/sdk/` (existing: `MatchSDKTest`,
   `SDKServiceTest`, `SampleSDKTest`, `ServiceCoverageTest`, `UtilTest`)
   plus XML fixtures in `src/test/resources/sample_files/`.
5. Push to your fork, open a PR against `mosip/mock-android-match-sdk`.

## Pull Request Guidelines

- Target `develop`; sign off commits (`git commit -s`, DCO).
- CI runs `./gradlew :matchsdk:assembleRelease` on push/PR to
  `master`/`develop`/`release*` — must build/assemble cleanly.
- `use-pr-linker.yml` auto-links PRs to issues via `mosip/kattu` — reference
  the tracking issue number in the PR description.
- Follow [MOSIP's contribution guidelines](https://docs.mosip.io/1.2.0/community/code-contributions).

## Repository-Specific Considerations

- Resist "improving" the matching algorithm toward realism — its job is
  predictable behavior for integration testing. If a threshold change is
  genuinely needed, call it out explicitly in the PR as an intentional mock
  behavior change, not a bug fix.
- `matchsdk` implements a versioned external interface (`IBioApiV2`).
  Changing `SampleSDK`/service-interface method signatures can break
  consumers (e.g. `android-registration-client`) — treat as breaking
  changes.
- `app` exists only for manual exercising; not a test substitute, not
  published.
- Instrumented tests (`src/androidTest/`) need a device/emulator and are
  not run by CI either — treat as developer-local, not a CI gate.

## Agent rules

### Do

1. Treat `matchsdk` as the product; `app` as a manual test harness only.
2. Run `./gradlew :matchsdk:test` (+ `:matchsdk:assembleRelease` if build
   config changed) before calling a change complete.
3. Add/update unit tests and XML fixtures for match/quality/extraction/
   conversion logic changes.
4. Flag any `IBioApiV2`-facing signature change as breaking in the PR.
5. Target `develop`; reference the tracking issue for the PR-linker.

### Do not

1. Don't commit `local.properties`, `build/`, `.idea`/`.gradle` state —
   already git-ignored.
2. Don't assume the commented-out `maven-publish` block is active.
3. Don't add real credentials, API keys, or network calls — must stay
   fully offline.
4. Don't rely on `src/androidTest/` as a CI gate, or assume CI runs any
   tests at all.
5. Don't split into per-module AGENTS.md files — this repo is small enough
   for one root file.
