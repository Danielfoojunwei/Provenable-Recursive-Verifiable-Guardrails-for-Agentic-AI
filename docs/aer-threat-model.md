# AER Threat Model

## Scope

Agent Evidence & Recovery (AER) provides **structural security guarantees** for agentic AI systems. It is designed to enforce control-plane integrity (CPI), memory integrity (MI), and provide verifiable evidence bundles and rollback capabilities.

AER operates as a reference monitor at the chokepoints where control-plane mutations and memory writes occur. It does **not** rely on LLM behavior, prompt secrecy, or text-based defenses.

## What AER Guarantees

### Control-Plane Integrity (CPI)

**Theorem basis**: Under assumptions A1–A3 (provenance completeness, principal accuracy, memory persistence), if the AER verifier enforces guard rules at every control-plane mutation, then no untrusted input can alter the control plane.

**In practice**:
- Skills install/enable/disable/update operations are gated through a single chokepoint
- Tool registry changes require USER or SYS principal
- Permission and gateway auth changes are guarded
- Every allow/deny decision is recorded as tamper-evident evidence

**Boundary**: CPI protects the control-plane state (permissions, integrations, policies). It does NOT protect against:
- Data-plane attacks (reading sensitive data through authorized tools)
- Social engineering where a legitimate USER approves a malicious change

### Memory Integrity (MI)

**Theorem basis**: Memory Write Integrity guarantees immutability of protected memory, taint blocking for writes with untrusted provenance, and session isolation for cross-session transfers.

**In practice**:
- Workspace memory files (SOUL.md, AGENTS.md, TOOLS.md, USER.md, IDENTITY.md, HEARTBEAT.md, MEMORY.md) are guarded at a single write chokepoint
- Writes from WEB, SKILL, CHANNEL, or EXTERNAL principals are denied by default
- Writes with tainted provenance (UNTRUSTED, INJECTION_SUSPECT, WEB_DERIVED, SKILL_OUTPUT) are denied
- All decisions are recorded as evidence

**Boundary**: MI does NOT protect against:
- Inference-layer attacks within a single turn (model reasoning manipulation)
- Read confidentiality or data exfiltration through model outputs
- User-channel attacks where humans paste malicious content voluntarily

### Tamper-Evident Evidence

**Guarantee**: The append-only hash chain (Merkle-style) ensures that:
- Any modification to the audit log is detectable
- Records are linked by SHA-256 hashes
- The full chain can be verified independently

**Boundary**: The chain does not prevent deletion of the entire log — it detects tampering within a chain. Physical security of the state directory is assumed.

### RVU Rollback

**Guarantee**: Snapshots capture content hashes of all files in scope. Rollback restores files to their exact snapshotted content and emits a verifiable Rollback record.

**Boundary**: Rollback restores file content but cannot reverse side effects (e.g., external API calls, network traffic). Session logs are NOT rolled back (they are audit evidence).

## Trust Lattice

```
SYS (trust level 5)
 └── USER (trust level 4)
      └── TOOL_AUTH (trust level 3)
           └── TOOL_UNAUTH (trust level 2)
                └── WEB, SKILL (trust level 1)
                     └── CHANNEL, EXTERNAL (trust level 0)
```

Principals are assigned based on **transport channel**, not content claims. This prevents confused-deputy attacks.

## Taint Model

Taint flags propagate conservatively: if any parent is tainted, the output is tainted. Taint flags:

| Flag | Bit | Meaning |
|------|-----|---------|
| UNTRUSTED | 0x01 | From untrusted source |
| INJECTION_SUSPECT | 0x02 | Potential injection payload |
| PROXY_DERIVED | 0x04 | Derived from proxy/forwarded request |
| SECRET_RISK | 0x08 | May contain secrets |
| CROSS_SESSION | 0x10 | Transferred across sessions |
| TOOL_OUTPUT | 0x20 | Output from tool execution |
| SKILL_OUTPUT | 0x40 | Output from skill execution |
| WEB_DERIVED | 0x80 | Derived from web/HTTP source |

## Assumptions

1. **A1 (Provenance Completeness)**: Every derived record tracks all data sources in its parent list
2. **A2 (Principal Accuracy)**: Principals are assigned from transport channels, not content
3. **A3 (Memory Persistence)**: Provenance chains survive store/load cycles
4. **A4 (Runtime Integrity)**: The AER runtime itself is not compromised
5. **A5 (Filesystem Access)**: The state directory has appropriate OS-level permissions

## What AER Does NOT Cover

- Model behavior during inference (AER operates structurally, not on model internals)
- Prompt injection within a single inference turn
- Data exfiltration through authorized read paths
- Physical compromise of the host system
- Availability attacks / performance degradation
- Social engineering of legitimate users
