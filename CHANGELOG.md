# Changelog

All notable changes to Aquatone Revamped are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Rebuilt Go 1.26 scanning pipeline with bounded TCP, HTTP, and screenshot concurrency.
- Darwin arm64/amd64, Linux arm64/amd64, and Windows amd64 build targets.
- Managed Chromium installation plus system and explicit browser selection.
- Offline interactive reports, perceptual screenshot clustering, blank-capture retries, and CSP hardening.
- TLS, DNS, redirect, response, and maintained Wappalyzer technology metadata.
- Versioned v2 session JSON, JSONL results, and legacy v1 session report migration.
- Rate limiting, status filters, body-size limits, graceful interrupt handling, and private output permissions.

### Changed

- Renamed the maintained project to Aquatone Revamped while retaining the `aquatone` binary name.
- Response bodies are no longer saved by default.
- Reports have no CDN or runtime network dependencies.

### Removed

- Subdomain-takeover claims based on stale embedded fingerprints.
- The legacy event-bus architecture and unmaintained dependencies.
- Custom v1 report templates, which are incompatible with the v2 data model.

### Fixed

- Preserve IPv6 URL brackets and probe known web ports from XML when service detection is absent.
- Copy referenced artifacts when regenerating a report into another directory.
- Apply custom `Host` headers correctly and reject rate limits that cannot produce a valid ticker interval.

## Original Aquatone history

Aquatone Revamped continues the MIT-licensed Aquatone project. Releases through v1.7.0 are documented in the [original repository](https://github.com/michenriksen/aquatone/releases).
