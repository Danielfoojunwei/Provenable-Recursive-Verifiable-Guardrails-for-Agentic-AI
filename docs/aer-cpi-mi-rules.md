# CPI/MI Guard Rules — Provenable.ai Surface Mapping (OpenClaw Integration)

## Overview

AER enforces Control-Plane Integrity (CPI) and Memory Integrity (MI) at structural chokepoints in the Provenable.ai runtime (compatible with OpenClaw and other agentic systems). This document maps guard rules to specific OpenClaw surfaces.

## Trust Lattice

```
SYS (5)  →  USER (4)  →  TOOL_AUTH (3)  →  TOOL_UNAUTH (2)  →  WEB/SKILL (1)  →  CHANNEL/EXTERNAL (0)
```

Principals are determined by **transport channel**, not by content claims:

| Channel | Principal |
|---------|-----------|
| Platform runtime / system migration | SYS |
| Authenticated user CLI session | USER |
| Authenticated tool API return | TOOL_AUTH |
| Unauthenticated tool output | TOOL_UNAUTH |
| HTTP scrape / web fetch | WEB |
| Skill file store / skill output | SKILL |
| Forwarded channel | CHANNEL |
| External / unknown | EXTERNAL |

## Control-Plane Integrity (CPI)

### Protected Surfaces

| Surface | Config Key Pattern | Description |
|---------|-------------------|-------------|
| Skills registry | `skills.install`, `skills.enable`, `skills.disable`, `skills.update` | Adding, enabling, disabling, or updating skills |
| Tool registry | `tools.register`, `tools.remove`, `tools.config` | Registering or removing tools |
| Permissions | `permissions.*` | Changing agent permissions |
| Gateway auth | `gateway.auth`, `gateway.token`, `gateway.password` | Gateway authentication changes |
| Node settings | `node.pairing`, `node.exec` | Node pairing and execution settings |

### Default Policy Rules

| Rule ID | Action | Condition | Description |
|---------|--------|-----------|-------------|
| `cpi-deny-untrusted` | DENY | principal in {Web, Skill, Channel, External, ToolUnauth, ToolAuth} | Block CPI changes from non-USER/SYS |
| `cpi-allow-authorized` | DENY → ALLOW | principal in {User, Sys} | Allow CPI changes from USER or SYS |

### Enforcement Point

All control-plane mutations MUST pass through `hooks::on_control_plane_change()`. This function:

1. Evaluates the policy against the request (principal + taint + approval flag)
2. Emits a `GuardDecision` record with verdict, rule ID, and rationale
3. If **allowed**: emits a `ControlPlaneChangeRequest` record and returns Ok
4. If **denied**: returns Err (caller must NOT apply the change)

## Memory Integrity (MI)

### Protected Files

| File | Path | Description |
|------|------|-------------|
| SOUL.md | `<workspace>/SOUL.md` | Agent identity and personality |
| AGENTS.md | `<workspace>/AGENTS.md` | Agent registry |
| TOOLS.md | `<workspace>/TOOLS.md` | Available tools |
| USER.md | `<workspace>/USER.md` | User preferences |
| IDENTITY.md | `<workspace>/IDENTITY.md` | Identity configuration |
| HEARTBEAT.md | `<workspace>/HEARTBEAT.md` | Heartbeat / status |
| MEMORY.md | `<workspace>/MEMORY.md` | Persistent memory (optional) |

### Default Policy Rules

| Rule ID | Action | Condition | Description |
|---------|--------|-----------|-------------|
| `mi-deny-tainted` | DENY | taint intersects {UNTRUSTED, INJECTION_SUSPECT, WEB_DERIVED, SKILL_OUTPUT} | Block writes with tainted provenance |
| `mi-deny-untrusted-principal` | DENY | principal in {Web, Skill, Channel, External} | Block writes from untrusted principals |
| `mi-allow-authorized` | DENY → ALLOW | principal in {User, Sys} and no taint | Allow clean writes from trusted principals |

### Enforcement Point

All workspace memory writes MUST pass through `workspace::write_memory_file()`. This function:

1. Validates the filename is a recognized memory file
2. Routes through `hooks::on_file_write()` which evaluates MI policy
3. If **allowed**: writes the file to disk and emits a `FileWrite` record
4. If **denied**: does NOT write and returns the denial record ID

## ConversationIO Guard (CIO) — Prompt Injection / Extraction Defense

The ConversationIO surface protects the conversation boundary between users
(or untrusted channels) and the LLM. It integrates all four published theorems.

### Threat: ZeroLeaks Attack Taxonomy

The ZeroLeaks OpenClaw Security Assessment demonstrated 91.3% injection success
and 84.6% extraction success against unprotected systems. The CIO guard
addresses this with two enforcement layers.

### Layer 1: Input Scanner (8 Detection Categories)

| Category | Taint Flags | Confidence | Theorem Basis |
|----------|-------------|------------|---------------|
| `SystemImpersonation` | `INJECTION_SUSPECT` + `UNTRUSTED` | 0.85-0.90 | CPI (A2: Principal Accuracy) |
| `IndirectInjection` | `INJECTION_SUSPECT` + `UNTRUSTED` | 0.85 | Noninterference |
| `BehaviorManipulation` | `INJECTION_SUSPECT` + `UNTRUSTED` | 0.85 | CPI (behavioral state) |
| `FalseContextInjection` | `INJECTION_SUSPECT` + `UNTRUSTED` | 0.80 | MI + Noninterference (A1) |
| `EncodedPayload` | `INJECTION_SUSPECT` + `UNTRUSTED` | 0.70-0.85 | Noninterference |
| `ExtractionAttempt` | `UNTRUSTED` | 0.75-0.95 | MI (read-side) |
| `ManyShotPriming` | `UNTRUSTED` | 0.70-0.90 | Noninterference |
| `FormatOverride` | `UNTRUSTED` | 0.80 | Noninterference |

Scanner verdict thresholds:
- **Block**: SystemImpersonation or ExtractionAttempt at confidence ≥ 0.9, OR ≥ 3 findings at confidence ≥ 0.75
- **Suspicious**: Any finding at confidence ≥ 0.7
- **Clean**: No findings above threshold

### Layer 2: Output Guard (Leaked-Content Detection)

Scans outbound LLM responses for leaked system prompt content:
- **Exact-match watchlist**: Internal tokens (SILENT_REPLY_TOKEN, buildSkillsSection, ${params.*})
- **Pattern watchlist**: Structural prompt patterns (skill loading, memory search, reply tags)
- **Section heuristic**: Detects multi-section prompt dumps (4+ section headers)

### Default Policy Rules

| Rule ID | Action | Condition | Description |
|---------|--------|-----------|-------------|
| `cio-deny-injection` | DENY | taint intersects {INJECTION_SUSPECT} | Block injection-suspect messages from ALL principals |
| `cio-deny-untrusted-tainted` | DENY | principal in {Web, Skill, Channel, External} AND taint intersects {UNTRUSTED} | Block tainted messages from untrusted principals |
| `cio-allow-clean` | ALLOW | (fallback) | Allow clean or USER messages without injection taint |

### Enforcement Points

**Input**: `guard.check_conversation_input()` — scans before LLM processes the message
**Output**: `guard.check_conversation_output()` — scans LLM response before delivery

### Session-Level Defense (v0.1.2 — Four Corollaries)

| Corollary | Theorem Basis | Implementation |
|-----------|---------------|----------------|
| Conversational Noninterference | Noninterference | `conversation_state.rs` — session-level taint accumulation, crescendo detection |
| CPI Behavioral Constraint | CPI Theorem | `scanner.rs` — canary injection → `INJECTION_SUSPECT` taint |
| MI Dynamic Token Discovery | MI Theorem | `output_guard.rs` — runtime watchlist from actual system prompt |
| Semantic Intent Detection | Noninterference | `scanner.rs` — regex verb+target extraction intent matching |

### Empirical Results (ZeroLeaks Benchmark)

```
Extraction: 4/13 blocked at input, 7/13 suspicious (tainted), 2/13 clean
Injection:  13/23 blocked at input, 9/23 suspicious (tainted), 1/23 clean
Output:     11/11 leaked patterns caught, 0 false positives

ZLSS:           10/10  →  1/10
Security Score:  2/100 →  90/100
```

## Skill Supply Chain Verification (v0.1.3 — ClawHavoc Defense)

### Surface

Pre-install skill package verification (`hooks::on_skill_install()`).

### ClawHavoc Attack Vectors Covered

| Vector | Attack | Detection | Severity |
|--------|--------|-----------|----------|
| V1 | Social engineering (`curl \| bash`) | Shell execution pattern regex | Critical |
| V2 | Reverse shell backdoor | Reverse shell pattern regex | Critical |
| V3 | Credential exfiltration (`.env`, SSH keys) | Credential access + exfiltration patterns | High/Critical |
| V4 | Memory poisoning (SOUL.md writes) | Memory file write pattern regex | Critical |
| V5 | Skill precedence exploitation | Name collision against existing registry | High |
| V6 | Typosquatting | Levenshtein distance ≤ 2 against popular skills | Medium |

### Enforcement Point

`hooks::on_skill_install()` must be called BEFORE `hooks::on_control_plane_change("skills.install", ...)`.
The verifier emits a tamper-evident `GuardDecision` record with full findings.

### Verdict Levels

| Verdict | Condition | Action |
|---------|-----------|--------|
| `Allow` | No findings or Info-only | Proceed to CPI guard |
| `RequireApproval` | Medium-severity findings | Prompt user for explicit approval |
| `Deny` | High or Critical findings | Block installation |

See [ClawHub Integration](clawhub-integration.md) for the full deep dive analysis.

## File Read Guard (v0.1.6 — MI Read-Side + Noninterference)

### Surface

Sensitive file access control (`hooks::on_file_read()`).

### Protected Patterns

| Category | Default Patterns | Action |
|----------|-----------------|--------|
| **Denied basenames** | `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `credentials`, `*.secret`, `.netrc`, `.pgpass` | DENY — read blocked entirely |
| **Tainted directories** | `.aws/*`, `.ssh/*`, `.gnupg/*`, `.docker/config.json`, `*token*`, `*password*` | ALLOW with `SECRET_RISK` taint propagated |

### Default Policy Rules

| Rule ID | Action | Condition | Description |
|---------|--------|-----------|-------------|
| `fs-deny-untrusted-sensitive` | DENY | principal in {Web, Skill, Channel, External} AND path matches denied pattern | Block untrusted reads of sensitive files |
| `fs-taint-sensitive-dir` | ALLOW + taint | path matches tainted pattern | Allow read but propagate `SECRET_RISK` (0x08) taint |
| `fs-allow-trusted` | ALLOW | principal in {User, Sys} | Trusted principals can read any file |

### Enforcement Point

`hooks::on_file_read()` must be called before file content is returned to the caller.
The guard emits a `GuardDecision` record with the file path, principal, and verdict.

### Defense in Depth

Even if the hook is bypassed (e.g., direct filesystem access), the scanner's
`SensitiveFileContent` category detects leaked credentials in tool output:
- AWS access keys (`AKIA...`)
- Private key headers (`-----BEGIN RSA PRIVATE KEY-----`)
- Connection strings with embedded passwords

### Theorem Basis

- **MI (read-side extension):** Protected memory artifacts include sensitive files
- **Noninterference:** Secret file content taints all downstream derivations via conservative propagation

---

## Network Egress Monitor (v0.1.6 — Noninterference + CPI)

### Surface

Outbound network request evaluation (`hooks::on_outbound_request()`).

### Domain Policy

| Category | Default Domains | Action |
|----------|----------------|--------|
| **Blocked (exfiltration services)** | `webhook.site`, `requestbin.com`, `pipedream.net`, `canarytokens.com`, `interact.sh`, `burpcollaborator.net` | DENY |
| **Allowlist** | Empty by default (all non-blocked allowed) | When non-empty: DENY everything not on list |

### Default Policy Rules

| Rule ID | Action | Condition | Description |
|---------|--------|-----------|-------------|
| `net-deny-blocked-domain` | DENY | domain matches blocklist | Block known exfiltration services |
| `net-deny-unlisted` | DENY | allowlist non-empty AND domain not on allowlist | Strict mode: only allow listed domains |
| `net-flag-large-payload` | ALLOW + taint | payload exceeds size limit | Flag large outbound payloads for review |
| `net-allow-trusted` | ALLOW | principal in {User, Sys} | Trusted principals can make any request |

### Enforcement Point

`hooks::on_outbound_request()` must be called before the HTTP request is sent.
The guard emits a `GuardDecision` record with the target URL, principal, and verdict.
A `NetworkRequest` record type captures the full request metadata for the audit chain.

### Pre-Install Detection

`skill_verifier.rs` detects hardcoded exfiltration URLs in skill code at install time,
blocking installation before any runtime execution occurs.

### Deployment Note

AER provides the policy layer. Full enforcement requires OS-level egress controls:
- **Squid/Envoy proxy:** Route all outbound HTTP through a proxy enforcing AER's domain policy
- **eBPF (Cilium/Falco):** Kernel-level network monitoring for socket-level enforcement
- **Firewall rules (iptables/nftables):** Block direct outbound except through the proxy

---

## Sandbox Audit (v0.1.6 — CPI + RVU)

### Surface

OS sandbox environment verification at session start (`hooks::on_session_start()`).

### Checks Performed

| Check | Source | What It Detects |
|-------|--------|----------------|
| Container detection | `/.dockerenv`, `/proc/1/cgroup`, `KUBERNETES_SERVICE_HOST` | Whether the process runs inside a container |
| Seccomp status | `/proc/self/status` Seccomp line | Seccomp filter mode (disabled=0, strict=1, filter=2) |
| Namespace isolation | `/proc/self/ns/` symlinks | PID, network, mount, user namespace isolation |
| Read-only root | Mount flags on `/` | Whether the root filesystem is read-only |
| Resource limits | `/proc/self/limits` | Max processes, open files, memory limits |

### Compliance Levels

| Level | Criteria | Alert |
|-------|----------|-------|
| `Full` | Container + seccomp filter + namespace isolation | None |
| `Partial` | Some but not all checks pass | HIGH alert |
| `None` | No sandboxing detected | CRITICAL alert |

### Evidence

The audit result is recorded as a tamper-evident `GuardDecision` record with all
individual check results, compliance score, and findings summary.

---

## Reverse Proxy Trust Detection

### Surface

Gateway configuration `gateway.trustedProxies`.

### Detection Rule

If `trustedProxies` contains overly permissive values (`0.0.0.0/0`, `*`, `::/0`), AER emits an audit **warning** record with `PROXY_DERIVED` taint. This is a detection-only check — it does NOT block the gateway from running.

### Rationale

An overly permissive trustedProxies setting means the gateway will trust `X-Forwarded-For` headers from any source, allowing IP spoofing and potential authentication bypass. AER detects this misconfiguration and records it as evidence.

## Policy Evaluation Order

1. Rules are evaluated in order (first match wins)
2. If no rule matches, the default action is **DENY** (fail-closed)
3. Every evaluation emits a `GuardDecision` record regardless of verdict

## Customization

Edit `<STATE_DIR>/.aer/policy/default.yaml` to add, remove, or reorder rules. The policy format supports:

- **Principal filters**: restrict which principals a rule applies to
- **Taint filters**: restrict based on taint bitset intersection
- **Approval requirement**: require explicit user approval flag

Example: Allow TOOL_AUTH to write memory with explicit approval:

```yaml
- id: mi-allow-tool-with-approval
  surface: DurableMemory
  action: Allow
  condition:
    principals: [ToolAuth]
    require_approval: true
  description: "Allow authenticated tool memory writes with explicit approval"
```

Insert this rule **before** the deny rules in the policy file.
