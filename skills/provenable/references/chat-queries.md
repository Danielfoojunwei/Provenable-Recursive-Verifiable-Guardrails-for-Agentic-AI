# Natural Language Query Mapping

This file maps natural language questions to the exact commands and JSON paths the agent should use.

## Protection Status

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Am I protected?" | `proven-aer prove --json` | `.protection.total_threats_blocked`, `.health.audit_chain_valid` |
| "How secure is my system?" | `proven-aer prove --json` | `.protection.protection_rate`, `.health` |
| "What has Provenable blocked?" | `proven-aer prove --json` | `.protection` summary |
| "Show protection report" | `proven-aer prove` | Full human-readable report |
| "Protection summary" | `proven-aer prove` | Protection section |

## Threat Alerts

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Any threats?" | `proven-aer prove --severity MEDIUM --limit 20 --json` | `.alerts` array |
| "Show critical alerts" | `proven-aer prove --severity CRITICAL --json` | `.alerts` filtered to CRITICAL |
| "Recent attacks" | `proven-aer prove --limit 10 --json` | `.alerts` last 10 |
| "CPI violations" | `proven-aer prove --category CPI --json` | `.alerts` + `.protection.cpi_violations_blocked` |
| "Memory integrity issues" | `proven-aer prove --category MI --json` | `.alerts` + `.protection.mi_violations_blocked` |
| "Injection attempts" | `proven-aer prove --category INJECTION --json` | `.alerts` with InjectionSuspect category |
| "Proxy issues" | `proven-aer prove --category PROXY --json` | `.alerts` + `.protection.proxy_misconfigs_detected` |

## System Health

| User says | Command | Response focus |
|-----------|---------|----------------|
| "System health" | `proven-aer status` | Full status output |
| "Is AER running?" | `proven-aer status` | Initialized state |
| "Is the audit chain valid?" | `proven-aer prove --json` | `.health.audit_chain_valid` |
| "Any warnings?" | `proven-aer prove --json` | `.health.warnings` |
| "How many records?" | `proven-aer prove --json` | `.health.record_count` |

## Guard Performance

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Guard performance" | `proven-aer prove --json` | `.metrics` section |
| "How fast are the guards?" | `proven-aer prove --json` | `.metrics.avg_eval_us`, `.metrics.p95_eval_us` |
| "Evaluations per second" | `proven-aer prove --json` | `.metrics.evals_per_sec` |
| "Guard latency" | `proven-aer prove --json` | `.metrics.p50_eval_us`, `.metrics.p95_eval_us`, `.metrics.p99_eval_us` |
| "How many denials?" | `proven-aer prove --json` | `.metrics.total_denials` |

## Snapshots and Rollback

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Take a snapshot" | `proven-aer snapshot create "user-requested" --scope full` | Snapshot ID and details |
| "List snapshots" | `proven-aer snapshot list` | All snapshots |
| "Roll back" | `proven-aer snapshot list` (show options, let user pick) | Then `proven-aer rollback <ID>` |
| "Undo last change" | `proven-aer snapshot list` (get latest) | Then `proven-aer rollback <ID>` |
| "Restore to before deploy" | `proven-aer snapshot list` (find by name) | Then `proven-aer rollback <ID>` |

## Evidence Bundles

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Export evidence" | `proven-aer bundle export` | Bundle path |
| "Verify bundle" | `proven-aer verify <PATH>` | Verification result |
| "Summarize bundle" | `aegx summarize <DIR>` | Record counts and verification |
| "Generate audit report" | `proven-aer report <PATH>` | Markdown report |

## Host Environment Queries (v0.1.6)

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Is my environment sandboxed?" | `proven-aer prove --json` | `.health` sandbox compliance |
| "Any file read blocks?" | `proven-aer prove --category MI --json` | File read guard denials in `.alerts` |
| "Any exfil attempts?" | `proven-aer prove --category INJECTION --json` | Network egress denials + DataExfiltration alerts |
| "Was anything blocked from reading secrets?" | `proven-aer prove --json` | SensitiveFileRead alerts in `.alerts` |
| "Network security" | `proven-aer prove --json` | NetworkExfiltration alerts + domain blocks |
| "Sandbox status" | `proven-aer prove --json` | SandboxDeficiency alerts (if any) |

## Response Formatting Guidelines

When answering protection queries:

1. Lead with the headline number (e.g., "42 threats blocked, audit chain VALID")
2. Highlight any CRITICAL or HIGH alerts
3. Show the protection rate as a percentage
4. Mention system health status
5. If there are warnings, surface them prominently
6. For performance queries, show p50/p95/p99 latencies
7. Always include the timestamp of the data
8. If AER is not initialized, tell the user to run `proven-aer init`

When answering snapshot/rollback queries:

1. List available snapshots with their names and dates
2. Confirm before executing a rollback
3. Remind that rollback only restores file content, not external actions
4. Show verification result after rollback
