# Changelog

All notable changes are documented here, in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `explain` strips leading environment-variable assignments before matching: allow rules see past known-safe variables (`NODE_ENV`, `LANG`, `NO_COLOR`), deny and ask rules see past any assignment.

## [0.1.0] - 2026-11-01

### Changed

- Contributing guide and PR template state the PR rules
- README covers common questions

### Added

- `lint` can emit SARIF 2.1.0 reports with stable descriptors for all finding codes.
- `explain` shows the permission decision for each subcommand.
- `lint` reports nine kinds of ineffective or risky rule.
- `explaining-permissions` skill and plugin manifest.
- Plugin icon referenced in the manifest.
