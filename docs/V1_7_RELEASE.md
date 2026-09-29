# RANDAR V1.8.0 — Remote Endpoint Operations Stability Fixes

## Scope

V1.7 makes multi-endpoint investigations operationally reliable through persistent agent state, capability negotiation, bounded secure job metadata, and safe cancellation.

### Persistent agent state

RANDAR persists:

- agent ID
- hostname/platform
- registration time
- last seen
- negotiated capabilities
- revocation timestamp

Agent tokens remain stored as SHA-256 digests only.

### Capability negotiation

Agents advertise capabilities on heartbeat. Capabilities are represented as:

- `collector:<name>`
- `rule:<name>`

The console exposes the negotiated capability inventory for each endpoint.

### Secure job metadata

Every dispatched JOCKY investigation job receives:

- job ID
- agent ID
- creation timestamp
- nonce
- expiration timestamp
- HMAC integrity signature

Scripts are still parsed/validated through the existing JOCKY allowlisted interpreter before dispatch. No arbitrary command execution is introduced.

### Cancellation

Pending and running jobs can be cancelled from the RANDAR console. A cancelled job is prevented from accepting a late result; the remote agent checks cancellation state before submitting completed results.

### Safety boundary

V1.7 does not add shell execution, arbitrary PowerShell, active exploitation, persistence installation, or security-control bypass. Remote execution remains execution of validated JOCKY investigations only.

## Verification

- Full regression suite: 75 passing
- Python compilation: required modules pass
- Existing V1.0–V1.6 functionality retained
- Existing JOCKY DSL scripts remain compatible
- Product identity: RANDAR
- DSL identity: JOCKY


## V1.8.0 stability fixes

- Fixed the Endpoint Agents capability modal crash caused by missing component state.
- Removed duplicate FastAPI capability, heartbeat and cancellation route/schema declarations.
- Added real investigation execution progress updates instead of the UI remaining at 5% until completion.
- Added regression coverage for interpreter progress callbacks.
- Corrected release metadata and documentation to reflect the verified 75-test suite.
