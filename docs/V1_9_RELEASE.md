# RANDAR V1.9.1 Bug-Fix Notes

This is a reliability patch over V1.9.0. The V1.9 Performance & Reliability scope remains unchanged.

- Generic collector timeout: 30 seconds.
- Heavy Windows telemetry profiles: modules/threads/memory regions/Event Log/Sysmon 45 seconds; PE metadata 60 seconds.
- Maximum investigation runtime remains 300 seconds.
- Cancellation now has a race-safe `cancelling` state and queued jobs cannot be resurrected.
- Frontend cancellation waits for the bounded worker to reach its terminal state.
- Active command progress is reported above the initial 5% startup marker.
- Collector status details accurately distinguish success, timeout, cancellation and error.

# RANDAR V1.9 — Performance & Reliability

## Objective

Make large investigations usable without sacrificing the controlled execution and forensic-integrity model.

## Pagination

The investigation archive now supports bounded server-side pages (`page`, `limit`, query/status/sort). The legacy no-parameter list response remains available for compatibility.

## Lazy loading

Large collector evidence is omitted from the V1.9 summary case response when a list exceeds 200 records. The console requests evidence pages only when the analyst opens the evidence source. Evidence filtering is performed server-side for the requested page.

## Collector timeouts

Collectors execute in daemon worker threads with a default **30-second** limit. Heavy Windows collectors use bounded 45–60 second profiles where process/module or PE inspection legitimately requires more work; a timed-out collector becomes a `timeout` result with duration/resource metadata; other collectors and analysis can continue. Context-local network evidence selection is propagated into the worker so V1.1/V1.2 network collection remains correct.

A timed-out worker is not force-killed. The bounded worker is isolated from the request/investigation control path, and its late return is ignored.

## Maximum runtime

The default investigation runtime limit is **300 seconds**. If reached, the investigation returns a partial result with the evidence already collected, an explicit termination reason, and resource accounting.

## Cancellation

Background jobs expose `POST /api/investigations/jobs/{job_id}/cancel`. Cancellation prevents further work from being scheduled and prevents persistence of a cancelled job. An already-running OS/API collector is not forcibly terminated; the collector remains subject to its bounded timeout.

## Maximum record and evidence limits

Each collector is limited to **10,000 list records** and **8 MiB** of serialized evidence. Truncation is explicit in `_randar_resource_limit` rather than silently dropping evidence.

## Resource accounting

Reports record:

- execution status
- termination reason
- elapsed milliseconds
- total/completed commands
- collector count
- successful/failed collectors
- timed-out collectors
- cancelled collectors
- records collected
- evidence bytes
- truncated collectors

Each collector also records duration, record count, truncation state and serialized resource bytes.

## Integrity

New V1.9 reports use integrity version 4. Verification remains backward compatible with earlier V1.0–V1.8 report shapes.

## Verification

- 83/83 regression tests passing
- Python compilation passing
- ZIP archive verification required before release freeze
- Production frontend build remains environment-dependent when npm package installation cannot complete.
