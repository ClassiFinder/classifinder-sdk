# Changelog

## 0.1.10 — 2026-11-12

### Added
- `CLASSIFINDER_BASE_URL` environment variable. When `base_url=` isn't passed, `ClassiFinder`,
  `AsyncClassiFinder`, and `ClassiFinderGuard` use it to target a self-hosted server
  (`ghcr.io/classifinder/classifinder`, see https://classifinder.ai/self-host). An explicit
  `base_url=` still wins; unset or empty falls back to `https://api.classifinder.ai`.

### Changed
- `base_url` now defaults to `None` (resolved as above) on both clients and on `ClassiFinderGuard`,
  which previously hard-coded the hosted URL.
