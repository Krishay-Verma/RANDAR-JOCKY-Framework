# RANDAR Frontend

React + Vite frontend for the RANDAR forensic investigation console.

## Current application areas

- Dashboard
- Investigations
- New Investigation
- Investigation Detail
- Global Search
- Remote Agents
- Network Evidence
- Windows Telemetry
- Injection Analysis
- JOCKY Bytecode
- Investigator Keys
- Sign In

## Development

From the repository root:

```bash
python start.py --dev
```

Or directly:

```bash
npm ci
npm run dev
```

## Production build

```bash
npm run build
```

The root `start.py` launcher can install frontend dependencies and build the production UI automatically.

## Capability catalog

The UI uses the backend capability catalog rather than maintaining an independent hard-coded list of collectors and analysis rules.

Backend endpoint:

```text
GET /api/catalog
```

This keeps the investigation editor aligned with the executable engine.


## V2.3 Runtime

The console includes a Runtime view for controlled JOCKY execution and structured execution telemetry.
