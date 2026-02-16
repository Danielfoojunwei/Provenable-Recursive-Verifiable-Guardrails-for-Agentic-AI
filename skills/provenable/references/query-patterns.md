# Query Patterns and Examples

## The /prove Query Interface

`proven-aer prove` is the primary query interface. It returns a structured response with protection summary, alerts, metrics, and health.

## JSON Response Structure

```json
{
  "version": "0.1.0",
  "generated_at": "2026-02-16T12:00:00Z",
  "protection": {
    "total_threats_blocked": 42,
    "cpi_violations_blocked": 15,
    "mi_violations_blocked": 8,
    "taint_blocks": 12,
    "proxy_misconfigs_detected": 2,
    "critical_alerts": 3,
    "high_alerts": 10,
    "medium_alerts": 15,
    "by_category": {
      "CpiViolation": 15,
      "MiViolation": 8,
      "TaintBlock": 12,
      "ProxyMisconfig": 2,
      "InjectionSuspect": 5
    },
    "by_principal": {
      "Web": 20,
      "Skill": 12,
      "External": 10
    },
    "total_evaluations": 1500,
    "protection_rate": 0.028
  },
  "alerts": [ ... ],
  "metrics": {
    "total_evaluations": 1500,
    "cpi_evaluations": 900,
    "mi_evaluations": 600,
    "total_denials": 42,
    "total_allows": 1458,
    "avg_eval_us": 15,
    "p50_eval_us": 12,
    "p95_eval_us": 35,
    "p99_eval_us": 80,
    "max_eval_us": 250,
    "min_eval_us": 5,
    "evals_per_sec": 250.0,
    "uptime_secs": 86400
  },
  "health": {
    "aer_initialized": true,
    "audit_chain_valid": true,
    "record_count": 1500,
    "audit_entries": 1500,
    "alert_count": 42,
    "state_dir": "/home/user/.proven",
    "warnings": []
  }
}
```

## Common Query Patterns

### Overall protection status

```bash
proven-aer prove --json
```

Parse `.protection.total_threats_blocked` for headline number.

### Critical alerts only

```bash
proven-aer prove --severity CRITICAL --json
```

### CPI violations in the last 24 hours

```bash
proven-aer prove --category CpiViolation --since "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" --json
```

On macOS:

```bash
proven-aer prove --category CpiViolation --since "$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)" --json
```

### Memory integrity violations

```bash
proven-aer prove --category MiViolation --json
```

### Last 5 alerts of any kind

```bash
proven-aer prove --limit 5 --json
```

### Guard performance (latency percentiles)

```bash
proven-aer prove --json | jq '.metrics'
```

### System health only

```bash
proven-aer prove --json | jq '.health'
```

### Protection rate (percentage of evaluations that resulted in a block)

```bash
proven-aer prove --json | jq '.protection.protection_rate * 100'
```

### Count of alerts by category

```bash
proven-aer prove --json | jq '.protection.by_category'
```

### Check if audit chain is valid

```bash
proven-aer prove --json | jq '.health.audit_chain_valid'
```

### Check for warnings

```bash
proven-aer prove --json | jq '.health.warnings'
```

## Evidence Bundle Workflow

### Export, verify, and summarize

```bash
# Export
proven-aer bundle export --agent my-agent
BUNDLE=$(ls -t ~/.proven/.aer/bundles/*.aegx.zip | head -1)

# Verify
proven-aer verify "$BUNDLE"

# Import and summarize
TMP=$(mktemp -d)
aegx import "$BUNDLE" "$TMP/bundle"
aegx summarize "$TMP/bundle"
rm -rf "$TMP"
```

### Snapshot workflow

```bash
# Create before risky operation
proven-aer snapshot create "pre-deploy" --scope full

# List all snapshots
proven-aer snapshot list

# Get the latest snapshot ID
SNAP=$(proven-aer snapshot list | tail -1 | awk '{print $1}')

# If something goes wrong, rollback
proven-aer rollback "$SNAP"
```

## Interpreting Exit Codes

### aegx verify

| Code | Meaning |
|------|---------|
| 0 | PASS — bundle integrity verified |
| 2 | TAMPERED — hash mismatch or broken audit chain |
| 3 | MALFORMED — schema validation failed |
| 4 | IOERROR — cannot read bundle |

### proven-aer (all commands)

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (arguments, I/O, verification failure) |

## Inline vs Blob Decision Rule

| Condition | Use |
|-----------|-----|
| Payload JSON ≤ 4096 bytes | `--inline` |
| Payload > 4096 bytes or binary | `aegx add-blob` first, then `--blob --mime --size` |
