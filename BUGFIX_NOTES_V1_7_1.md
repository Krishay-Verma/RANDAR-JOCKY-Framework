# RANDAR v1.8.0 Bug-Fix Notes

## Fixed issues

1. **Endpoint Agents crash — `capabilities is not defined`**
   - Moved the capability-modal state to the `Agents` page where it is rendered.
   - The capability inventory now opens without taking down the route.

2. **Windows Telemetry route render failure**
   - Audited the route/component data flow and rebuilt the affected source with the route-error recovery retained.
   - The Windows page now uses the stable shared helpers and backend registry response shape.

3. **Long-running investigation progress stuck at 5%**
   - Added progress callbacks to the JOCKY interpreter.
   - Background investigations now advance through command execution, report construction, persistence, and audit stages.
   - Full-sweep progress follows the actual executed command count rather than jumping from 5% to 90%.

4. **Duplicate V1.7 API declarations**
   - Removed duplicate heartbeat schema, capability route, cancellation route, and duplicated registration logic.

5. **Release metadata/documentation drift**
   - Corrected the release version to 1.8.0.
   - Corrected V1.7 verification documentation to the actual 75-test result.
   - Corrected the release document pointer.

6. **UI status refresh**
   - Cancellation/revocation actions now await the refresh so the console does not briefly display stale state.

## Verification

- Python compileall: PASS
- Full regression suite: **75 passed**
- Fresh ZIP extraction verification: PASS
- Frontend production Vite build: **not verified in this environment** because the npm dependency install transport timed out. The release intentionally contains no stale `node_modules` or `dist` directory.
