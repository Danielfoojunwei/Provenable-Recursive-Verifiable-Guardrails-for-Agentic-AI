# Guard Policies — CPI and MI Rules

## Default Policy

The default policy ships with AER and is stored at `~/.proven/.aer/policy/default.yaml`. It enforces the CPI and MI theorems from the Provenable.ai security model.

## CPI Rules (Control-Plane Integrity)

### Rule: cpi-deny-untrusted

**Surface:** ControlPlane
**Action:** Deny
**Condition:** Principal is Web, Skill, Channel, or External
**Description:** Untrusted principals cannot modify control-plane state.

CPI-protected surfaces:
- Skills registry (install, enable, disable, update, remove)
- Tool registry (register, remove, configure)
- Permissions configuration
- Gateway authentication settings
- Node/server settings

### Rule: cpi-deny-tainted

**Surface:** ControlPlane
**Action:** Deny
**Condition:** Any taint flag is set
**Description:** Tainted data cannot influence control-plane state.

### Rule: cpi-require-approval

**Surface:** ControlPlane
**Action:** Deny
**Condition:** User or Sys principal without explicit approval
**Description:** Even trusted principals need explicit approval for control-plane changes.

### Rule: cpi-allow-approved-user

**Surface:** ControlPlane
**Action:** Allow
**Condition:** Principal is User or Sys, AND approved=true, AND no taint
**Description:** Approved, untainted changes from trusted principals are allowed.

## MI Rules (Memory Integrity)

### Rule: mi-deny-untrusted

**Surface:** DurableMemory
**Action:** Deny
**Condition:** Principal is Web, Skill, Channel, or External
**Description:** Untrusted principals cannot write to persistent memory files.

### Rule: mi-deny-tainted

**Surface:** DurableMemory
**Action:** Deny
**Condition:** Any taint flag is set
**Description:** Tainted data cannot overwrite memory files.

### Rule: mi-require-approval

**Surface:** DurableMemory
**Action:** Deny
**Condition:** User or Sys principal without explicit approval
**Description:** Memory writes require explicit approval even from trusted principals.

### Rule: mi-allow-approved-user

**Surface:** DurableMemory
**Action:** Allow
**Condition:** Principal is User or Sys, AND approved=true, AND no taint
**Description:** Approved, untainted writes from trusted principals are allowed.

## Custom Policies

You can create custom policy packs in YAML format. Each policy must pass structural and safety validation:

- At least one CPI deny rule for untrusted principals must exist
- At least one MI deny rule for untrusted principals must exist
- Policy files are integrity-checked with SHA-256 on load

### Policy YAML Format

```yaml
version: "1.0"
name: custom-policy
rules:
  - id: custom-rule-1
    surface: ControlPlane
    action: Deny
    condition:
      principals: [Web, Skill, Channel, External]
    description: "Block untrusted principals from control plane"

  - id: custom-rule-2
    surface: DurableMemory
    action: Deny
    condition:
      taint_any: 255
    description: "Block any tainted writes to memory"

  - id: custom-rule-3
    surface: ControlPlane
    action: Allow
    condition:
      principals: [User, Sys]
      require_approval: true
    description: "Allow approved changes from trusted principals"
```

Place custom policies at `~/.proven/.aer/policy/default.yaml`.

## File Read Guard Rules (v0.1.6)

### Rule: fs-deny-untrusted-sensitive

**Surface:** FileSystem
**Action:** Deny
**Condition:** Principal is Web, Skill, Channel, or External AND path matches denied basename pattern
**Description:** Block untrusted reads of sensitive files (.env, *.pem, *.key, id_rsa*, credentials).

### Rule: fs-taint-sensitive-dir

**Surface:** FileSystem
**Action:** Allow + SECRET_RISK taint
**Condition:** Path matches tainted directory pattern (.aws/*, .ssh/*, .gnupg/*)
**Description:** Allow read but propagate SECRET_RISK (0x08) taint to all downstream derivations.

### Rule: fs-allow-trusted

**Surface:** FileSystem
**Action:** Allow
**Condition:** Principal is User or Sys
**Description:** Trusted principals can read any file.

## Network Egress Rules (v0.1.6)

### Rule: net-deny-blocked-domain

**Surface:** NetworkIO
**Action:** Deny
**Condition:** Target domain matches blocklist (webhook.site, requestbin.com, pipedream.net, canarytokens.com, interact.sh, burpcollaborator.net)
**Description:** Block outbound requests to known exfiltration services.

### Rule: net-deny-unlisted

**Surface:** NetworkIO
**Action:** Deny
**Condition:** Allowlist is non-empty AND target domain is not on allowlist
**Description:** In strict mode, deny all requests to domains not on the allowlist.

### Rule: net-flag-large-payload

**Surface:** NetworkIO
**Action:** Allow + taint
**Condition:** Outbound payload exceeds configured size limit
**Description:** Flag large outbound payloads for review.

### Rule: net-allow-trusted

**Surface:** NetworkIO
**Action:** Allow
**Condition:** Principal is User or Sys
**Description:** Trusted principals can make any outbound request.

## Guard Evaluation Order

1. Rules are evaluated in order (first match wins)
2. If no rule matches, the default verdict is **Deny** (deny-by-default architecture)
3. Every evaluation produces a `GuardDecision` record in the audit chain
4. Denied evaluations emit a `ThreatAlert` with appropriate category and severity
5. Denial rate limiting prevents log flooding (100 denials per 60 seconds)

## Guard Metrics

Every guard evaluation is timed and recorded:

```json
{
  "total_evaluations": 1500,
  "cpi_evaluations": 900,
  "mi_evaluations": 600,
  "total_denials": 42,
  "total_allows": 1458,
  "avg_eval_us": 15,
  "p50_eval_us": 12,
  "p95_eval_us": 35,
  "p99_eval_us": 80,
  "evals_per_sec": 250.0
}
```

Access via: `proven-aer prove --json` (see `.metrics` in response)
