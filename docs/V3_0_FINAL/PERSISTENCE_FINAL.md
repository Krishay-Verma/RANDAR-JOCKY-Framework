# Persistence Forensics — Final

## Windows coverage

| Surface | Source | Normal baseline | Review signals |
|---|---|---|---|
| Run / RunOnce | HKLM/HKCU CurrentVersion\Run* | signed installed software | unsigned target, unusual location, suspicious arguments, recent creation |
| Scheduled Tasks | Task Scheduler / task XML | vendor/Windows updaters | multiple independent risk signals; Temp alone is insufficient |
| Services | SCM + service registry | signed service binaries | DACL write access, unsigned target, unusual account/path, configuration anomaly |
| WMI subscriptions | `root\subscription` | usually sparse | permanent filters/consumers with executable/command actions |
| IFEO | Image File Execution Options | uncommon administrative configuration | Debugger/VerifierDlls on unexpected image |
| Winlogon | Winlogon registry | Windows defaults | non-default Shell/Userinit/Notify/GinaDLL values |
| AppInit | Windows registry | usually disabled/empty | unexpected DLLs or enabled loading |
| COM hijacking | HKCU\Software\Classes\CLSID | legitimate per-user COM overrides | unexpected server paths, unsigned DLLs |
| BITS | BITS job database/API | downloads and update activity | unexpected owner/path/remote source |
| Startup folders | user + common Startup | installed application shortcuts | unsigned/unusual executable target |
| Browser extensions | browser profile directories | known installed extensions | unexpected extension, unsigned/unusual files |
| Office add-ins | HKCU Office Addins | known enterprise/vendor add-ins | unexpected add-in/server path |
| LSA auth packages | HKLM Control\Lsa | Windows/vendor defaults | unexpected package names/paths |
| Service ImagePath | SCM/registry | quoted exact executable path | unquoted path with spaces or altered path |
| ServiceDll | service Parameters | signed vendor DLL | unsigned/unexpected ServiceDll |

## Scoring principle

No single weak signal should produce a high-severity persistence finding. The scoring model combines path, signature, publisher, file age, arguments, task/service account, and configuration anomalies.

A valid signature from a trusted publisher reduces severity only when the signature itself is valid. An untrusted publisher is not automatically malicious; it remains a contextual signal.

## Service write access

The service writable-path detector uses Windows DACL evidence where available. It evaluates relevant principal SIDs and write/modify/full-control rights. It does not infer write access from a path string and does not use `os.access()` as the primary forensic decision.

If ACL inspection cannot be performed, the result is `unknown`.

## Clean-system target

The regression target is fewer than 15 findings on the clean fixture, with no high/critical finding unless an independent anomalous signal such as an unsigned or otherwise materially suspicious executable is present.
