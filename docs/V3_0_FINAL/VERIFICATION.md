# Verification — v3.0.0 Final

## Regression suite

**165 passed, 0 failed**.

Coverage includes:

- persistence false-positive regression
- Windows DACL parsing
- environment-variable expansion
- Startup `.lnk` handling
- scheduled-task scoring
- finding deduplication
- stable finding IDs
- collector evidence references
- mandatory limitations/next-check fields
- report/evidence integrity
- elevation and coverage reporting
- WMI/IFEO/Winlogon/AppInit/COM/BITS/Startup/extension/Office/LSA coverage
- software/kernel flags
- background investigation jobs
- clipboard/browser metadata collector registration
- the exact `%windir%\\System32\\SecurityHealthSystray.exe` path that previously produced `bad escape \\W at position 2`

## Static verification

`python -m compileall -q jocky` must pass.

The release process removes Python caches, test caches, and local runtime artifacts before packaging.

## Frontend build note

A production Vite build is not claimed unless the dependency set can be installed in the build environment. The source-level regression suite remains authoritative for the included frontend changes in an offline packaging environment.
