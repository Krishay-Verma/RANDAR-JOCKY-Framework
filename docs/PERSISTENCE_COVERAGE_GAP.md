# Persistence Coverage Gap — RANDAR vs Autoruns vs PersistenceSniper

| Area | RANDAR V2.9.0 | Sysinternals Autoruns | PersistenceSniper | Gap / next work |
|---|---|---|---|---|
| Run / RunOnce | Covered | Covered | Covered | Enrichment and scoring hardened |
| Startup folders | Covered + all profiles | Covered | Covered | Broader profile and timestamp handling |
| Scheduled Tasks | Covered | Covered | Covered | Event-linked creation time + multi-signal scoring |
| Services | Covered | Covered | Covered | DACL, unquoted ImagePath, ServiceDll |
| Winlogon | Covered | Covered | Covered | Baseline and signer enrichment |
| AppInit DLLs | Covered | Covered | Covered | Native + 32-bit views |
| IFEO | Covered | Covered | Covered | Debugger/Verifier values |
| WMI permanent subscriptions | Covered | Covered | Covered | Consumer/filter/binding correlation can be expanded |
| COM hijacking | HKCU CLSID overrides covered | Broad COM/shell-extension coverage | Covered through several COM checks | Expand TreatAs/ProgID/TypeLib families |
| BITS | Covered | Covered | Covered | More job/notification variants |
| Browser extensions | Chromium-family metadata covered | Browser helper/add-on categories | Covered through extension-related checks | Expand Firefox/enterprise policy surfaces |
| Office add-ins | Covered | Office-related autostarts covered | Covered | Expand templates/VBA/test-DLL families |
| LSA/auth packages | Covered | Security provider categories | Covered | Broaden provider/package baselines |
| Shell extensions / Explorer extensions | Partial | Extensive | Extensive | Add dedicated registry/COM families |
| Winsock providers | Not dedicated | Covered | Covered | Add dedicated collector/rule |
| Boot Execute | Not dedicated | Covered | Covered | Add dedicated collector/rule |
| Scheduled-task files/ghost tasks | Partial | Covered | Dedicated checks | Add task-file consistency checks |
| Accessibility / Assistive Technology | Not dedicated | Covered categories | Covered | Add dedicated collector/rule |
| App Paths / Protocol handlers | Not dedicated | Covered | Covered | Add dedicated registry surfaces |
| Office templates / VBA monitors | Not dedicated | Covered categories | Covered | Add dedicated collector/rule |
| Security-support / AMSI providers | Not dedicated | Covered categories | Covered | Add provider baseline |

Microsoft describes Autoruns as covering Startup, Run/RunOnce, shell extensions, browser helper objects, Winlogon notifications, auto-start services, AppInit DLLs, image hijacks, Winsock providers and additional autostart categories. PersistenceSniper documents a much larger technique/check matrix and supports whitelists and selective high-false-positive checks. The comparison above is therefore intentionally conservative: it records what RANDAR has implemented in its current evidence model and where the mature tools still expose more specialized persistence families.
