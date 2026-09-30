# v3.0.0 Final Release Notes

- Finalized the V2.9 persistence-hardening baseline.
- Fixed the Windows Startup Items `bad escape \\W at position 2` exception by making environment-variable replacement literal-safe and correcting Windows fallback paths.
- Added a regression test for that exact failure mode.
- Added privacy-bounded clipboard metadata, browser history metadata, and browser cookie metadata collectors.
- Synchronized Domain Expansion JOCKY templates with the live collector registry.
- Updated current-state metadata to 32 collectors / 57 analysis rules.
- Updated product/version documentation for SIH26148 alignment.
- 165 regression tests pass.
