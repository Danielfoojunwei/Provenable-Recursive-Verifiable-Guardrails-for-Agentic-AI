# Alert Categories and Severities

## Threat Categories

### CpiViolation

Control-Plane Integrity violation attempt. An untrusted principal tried to modify a CPI-protected surface (skills registry, tool registry, permissions, gateway auth, server config).

**Typical trigger:** A skill or web input tries to install a new skill or change permissions.

**Severity:** HIGH or CRITICAL (CRITICAL if repeated attempts detected).

### MiViolation

Memory Integrity violation attempt. An untrusted or tainted source tried to write to a protected memory file.

**Protected files:** SOUL.md, AGENTS.md, TOOLS.md, USER.md, IDENTITY.md, HEARTBEAT.md, MEMORY.md

**Typical trigger:** A tool output or web-derived content tries to overwrite SOUL.md.

**Severity:** HIGH or CRITICAL.

### TaintBlock

An action was blocked because the data carried taint flags indicating untrusted provenance.

**Typical trigger:** Cross-session data or tool output tries to modify control plane or memory.

**Severity:** MEDIUM or HIGH.

### ProxyMisconfig

Proxy misconfiguration detected. The gateway's `trustedProxies` configuration allows overly permissive origins (`0.0.0.0/0`, `*`, `::/0`).

**Typical trigger:** Gateway starts with wildcard proxy trust.

**Severity:** HIGH.

### RateLimitExceeded

Guard denial rate limit exceeded. More than 100 denials in 60 seconds, indicating a possible log flooding attack.

**Typical trigger:** Automated script hammering a denied endpoint.

**Severity:** CRITICAL.

### InjectionSuspect

Suspected injection attack. Data flagged with the INJECTION_SUSPECT taint bit.

**Typical trigger:** Input containing prompt injection patterns or command injection attempts.

**Severity:** CRITICAL.

---

## Alert Severities

| Severity | Meaning | Action |
|----------|---------|--------|
| INFO | Informational event, no threat | Log only |
| MEDIUM | Suspicious activity detected | Monitor, investigate if repeated |
| HIGH | Active threat blocked by guard | Review alert details, check provenance |
| CRITICAL | Active attack pattern detected | Immediate escalation to user |

---

## Taint Flags

Bitflags propagated conservatively through the provenance chain. Any tainted parent taints the output.

| Flag | Bit | Meaning |
|------|-----|---------|
| UNTRUSTED | 0x01 | Data from untrusted source |
| INJECTION_SUSPECT | 0x02 | Suspected injection attack |
| PROXY_DERIVED | 0x04 | Derived from proxy headers |
| SECRET_RISK | 0x08 | Contains potential secrets |
| CROSS_SESSION | 0x10 | From a different session |
| TOOL_OUTPUT | 0x20 | Output from tool execution |
| SKILL_OUTPUT | 0x40 | Output from skill execution |
| WEB_DERIVED | 0x80 | From web-sourced input |

---

## Principal Trust Levels

| Principal | Trust Level | Can Modify CP | Can Write Memory |
|-----------|-------------|---------------|------------------|
| Sys | 5 | Yes | Yes |
| User | 4 | Yes | Yes |
| ToolAuth | 3 | No | Yes (if untainted) |
| ToolUnauth | 2 | No | Yes (if untainted) |
| Web | 1 | No | No |
| Skill | 1 | No | No |
| Channel | 0 | No | No |
| External | 0 | No | No |

---

## ThreatAlert JSON Structure

```json
{
  "alert_id": "sha256-derived-id",
  "timestamp": "2026-02-16T12:00:00Z",
  "severity": "CRITICAL",
  "category": "CpiViolation",
  "summary": "Skill principal attempted to modify skills.registry",
  "principal": "Skill",
  "taint": 65,
  "surface": "ControlPlane",
  "rule_id": "cpi-deny-untrusted",
  "record_id": "rec-abc123",
  "target": "skills.registry",
  "blocked": true
}
```
