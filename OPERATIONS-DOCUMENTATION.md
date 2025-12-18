# MAGMA Framework Detection Repository - Operations & Process Documentation

## Table of Contents
1. [Repository Overview](#repository-overview)
2. [Framework Architecture](#framework-architecture)
3. [Naming Conventions](#naming-conventions)
4. [Triage Playbook Naming Convention](#triage-playbook-naming-convention)
5. [Detection Scope Indicators](#detection-scope-indicators)
6. [Rule Structure and Standards](#rule-structure-and-standards)
7. [Available Log Sources and Data Sources](#available-log-sources-and-data-sources)
8. [Triage Playbook Integration](#triage-playbook-integration)
9. [Rule Creation Process](#rule-creation-process)
10. [Rule Review and Improvement Process](#rule-review-and-improvement-process)
11. [Quality Standards and Best Practices](#quality-standards-and-best-practices)
12. [Mapping Data Sources to Detection Capabilities](#mapping-data-sources-to-detection-capabilities)

---

## Repository Overview

### Purpose
This repository maintains detection rules for the MAGMA framework, providing comprehensive security monitoring and threat detection capabilities aligned with the MITRE ATT&CK framework.

### Framework
MAGMA Framework Detection Sheet - A hierarchical structure of detection use cases and rules organized by MITRE ATT&CK tactics and techniques.

### Rule Format
All rules are written in Sigma format, enabling deployment across multiple SIEM platforms while maintaining vendor-neutral detection logic.

---

## Framework Architecture

### Hierarchical Structure

The repository follows a three-tier hierarchical structure:

#### **L1: Use Case Categories (MITRE ATT&CK Tactics)**

L1 represents the highest level of categorization, mapping directly to MITRE ATT&CK tactics. Each L1 category represents a threat category or attack lifecycle phase.

**L1 Categories:**

| Code | Category Name | MITRE Tactic | Description |
|------|---------------|--------------|-------------|
| REC | Reconnaissance | TA0043 | Initial reconnaissance and target identification |
| INA | Initial Access | TA0001 | Attacker gains initial foothold through phishing, exploits, or stolen credentials |
| EXE | Execution | TA0002 | Attacker runs malicious code or commands on compromised systems |
| PER | Persistence | TA0003 | Mechanisms to maintain long-term access across restarts and credential changes |
| PRE | Privilege Escalation | TA0004 | Increasing access levels to gain higher permissions or administrative control |
| DFE | Defence Evasion | TA0005 | Hiding activities to avoid detection by security tools |
| CRA | Credential Access | TA0006 | Stealing or capturing authentication materials (passwords, tokens, hashes) |
| DIS | Discovery | TA0007 | Exploring environment to learn about systems, networks, users, and defenses |
| LAT | Lateral Movement | TA0008 | Moving from one system to another to expand access across environment |
| COL | Collection | TA0009 | Gathering data of interest from systems, files, or network locations |
| CNC | Command & Control | TA0011 | Establishing communication channels to remotely control compromised systems |
| EXF | Exfiltration | TA0010 | Transferring stolen data out of the network to external locations |
| IMP | Impact | TA0040 | Causing damage or disruption (encryption, destruction, service interruption) |

#### **L2: Use Cases (Specific Attack Techniques)**

L2 represents specific attack techniques or methods within each L1 category. Each L2 use case focuses on a particular approach attackers use to accomplish the tactic.

**Structure:**
- Format: `[L1-CODE]-[Sequential-Number]-[Use Case Name]`
- Example: `EXE-004-WMI Execution`
- Example: `CRA-001-Brute Force`

**Characteristics:**
- Maps to specific MITRE ATT&CK techniques or sub-techniques
- Groups related detection rules targeting the same attack method
- Serves as a folder container for L3 rules

#### **L3: Individual Detection Rules**

L3 represents individual, granular detection rules that identify specific indicators or behaviors.

**Structure:**
- Format: `[L1-CODE]-[L2-Number]-[Playbook-ID]-[Sequential-Number]-[Descriptive Rule Name].yml`
- Example: `EXE-004-001-0001-wmic.exe Process Call Create Execution.yml`
- Example: `CRA-001-002-0001-Password Guessing - Multiple Failed Logins Same Source - Windows.yml`
- Example: `CNC-001-003-0001-Suspicious Outbound Connection to Known C2 Domain.yml`

**Components:**
- **L1-CODE**: Three-letter uppercase category code (e.g., EXE, CRA, DFE)
- **L2-Number**: Three-digit L2 use case number (e.g., 001, 004, 012)
- **Playbook-ID**: Three-digit triage playbook identifier (links rule to investigation runbook)
  - `000` indicates no specific playbook assigned yet
  - Non-zero values link to specific triage procedures
- **Sequential-Number**: Four-digit rule sequence number (e.g., 0001, 0002, 0015)
- **Descriptive Rule Name**: Clear description of detection

**Characteristics:**
- Executable Sigma YAML detection rule
- Contains specific detection logic, conditions, and filters
- Targets specific log sources and event types
- Includes false positive considerations and severity levels
- Links to triage playbook for alert investigation guidance

**Note on Detection Scope:**
While the filename does not include a scope indicator, each rule's detection scope (Endpoint, Network, Web Application, or Authentication) is determined by its primary telemetry source and logsource configuration. This information is documented in the rule's metadata and can be used for categorization and coverage analysis.

---

## Naming Conventions

### Directory Naming

**L1 Directories:**
```
[L1-CODE]-[Full Category Name]
```
Examples:
- `EXE-Execution`
- `CRA-Credential Access`
- `DFE-Defence Evasion`

**L2 Directories:**
```
[L1-CODE]-[L2-Number]-[Use Case Name]
```
Examples:
- `EXE-004-WMI Execution`
- `CRA-001-Brute Force`
- `DIS-012-System Information Discovery`

### File Naming (L3 Rules)

**Format:**
```
[L1-CODE]-[L2-Number]-[Playbook-ID]-[Rule-Number]-[Descriptive-Name].yml
```

**Components:**
- **L1-CODE**: Three-letter uppercase category code (e.g., EXE, CRA, DFE)
- **L2-Number**: Three-digit L2 use case number (e.g., 001, 004, 012)
- **Playbook-ID**: Three-digit triage playbook identifier (e.g., 000, 001, 015)
  - References the investigation/triage runbook for this rule
  - `000` indicates no specific playbook assigned yet
  - Non-zero values link to specific triage procedures
- **Rule-Number**: Four-digit sequential rule number (e.g., 0001, 0002, 0015)
- **Descriptive-Name**: Clear, concise description of what the rule detects

**Examples:**
```
EXE-004-000-0001-wmic.exe Process Call Create Execution.yml
CRA-006-000-0020-Dump LSASS.exe Memory using ProcDump.yml
DFE-001-000-0001-PowerShell Base64 Encoded Command Execution.yml
CNC-001-005-0001-Suspicious Outbound Connection to Known C2 Domain.yml
INA-002-008-0001-SQL Injection Attempt in URL Parameters.yml
CRA-001-002-0001-Multiple Failed Authentication Attempts.yml
```

**Playbook ID Usage:**
- When a rule is created without a triage playbook, use `000`
- As triage playbooks are developed, update the Playbook-ID field
- Multiple rules can share the same Playbook-ID if they follow the same investigation procedure
- Playbook IDs enable analysts to quickly access investigation guidance when triaging alerts

### Rule ID Naming (Within YAML)

**Format:**
```yaml
id: [UPPERCASE-L1-CODE]-[L2-NUMBER]-[PLAYBOOK-ID]-[RULE-NUMBER]
```

**Examples:**
```yaml
id: EXE-004-000-0001
id: CRA-001-002-0001
id: DFE-005-015-0020
id: CNC-001-005-0005
id: INA-002-008-0012
```

**Rules:**
- All UPPERCASE for L1 code
- Numbers remain as-is (three digits for L2 and Playbook-ID, four digits for rule number)
- Hyphens as separators
- Must exactly match the filename structure (excluding descriptive name)
- Playbook-ID must be included (use `000` if no playbook assigned)

---

## Triage Playbook Naming Convention

### Overview

Triage playbooks are standalone investigation runbooks that provide step-by-step guidance for analysts responding to specific types of alerts. Each playbook has a unique three-digit identifier that links to detection rules through the Playbook-ID field.

### Playbook Naming Format

**Format:**
```
PLAYBOOK-[Playbook-ID]-[Descriptive-Name].md
```

**Components:**
- **PLAYBOOK**: Fixed prefix (all uppercase)
- **Playbook-ID**: Three-digit unique identifier (001-999)
- **Descriptive-Name**: Clear, concise description of the investigation focus

**Examples:**
```
PLAYBOOK-001-Generic-Alert-Triage.md
PLAYBOOK-005-LSASS-Memory-Dumping-Investigation.md
PLAYBOOK-012-Credential-Access-from-Password-Stores.md
PLAYBOOK-023-WMI-Remote-Execution.md
PLAYBOOK-042-Kerberos-Ticket-Attacks.md
PLAYBOOK-108-Web-Shell-Investigation.md
```

### Playbook ID Assignment Strategy

#### **ID Ranges (Recommended Organization)**

| ID Range | Category | Purpose |
|----------|----------|---------|
| 001-099 | General/Cross-Cutting | Generic procedures, multi-technique playbooks, foundational investigations |
| 100-199 | Initial Access & Reconnaissance | Phishing, web exploitation, VPN compromise, network scanning |
| 200-299 | Execution & Persistence | Process execution, scheduled tasks, service creation, startup persistence |
| 300-399 | Privilege Escalation & Credential Access | Credential dumping, token manipulation, Kerberos attacks, password spraying |
| 400-499 | Defense Evasion | Obfuscation, AV/EDR tampering, log clearing, masquerading |
| 500-599 | Discovery & Lateral Movement | Network enumeration, AD reconnaissance, remote execution, share access |
| 600-699 | Collection & Exfiltration | Data staging, archive creation, exfiltration channels |
| 700-799 | Command & Control | C2 beaconing, tunneling, proxy usage, remote access tools |
| 800-899 | Impact | Ransomware, data destruction, service disruption |
| 900-999 | Reserved/Special | Platform-specific, compliance-driven, or custom procedures |

**Note:** These ranges are recommendations, not strict requirements. Assign IDs based on organizational needs and workflow.

#### **Assignment Principles**

**1. Technique-Based Grouping:**
- Group related techniques under the same playbook when investigation steps are identical
- Example: All LSASS dumping variants (ProcDump, comsvcs.dll, Task Manager, NanoDump) → PLAYBOOK-005

**2. Scope Consideration:**
- Consider creating separate playbooks for different detection scopes (Endpoint vs. Network vs. Web)
- Example:
  - PLAYBOOK-320-Endpoint-Credential-Dumping.md
  - PLAYBOOK-321-Network-Credential-Relay.md

**3. Complexity-Based Splitting:**
- Complex investigations may warrant dedicated playbooks even if techniques are similar
- Simple variations can share playbooks with conditional branching

**4. Platform-Specific Playbooks:**
- Create separate playbooks for platform-specific investigations when tools and artifacts differ significantly
- Example:
  - PLAYBOOK-510-Windows-Lateral-Movement-Investigation.md
  - PLAYBOOK-511-Linux-SSH-Lateral-Movement.md

### Playbook File Format

**File Type:** Markdown (.md)

**Recommended Structure:**
```markdown
# PLAYBOOK-[ID]-[Name]

## Overview
- **Playbook ID:** [Three-digit ID]
- **Related MITRE Techniques:** [T1234, T5678]
- **Detection Scope:** [Endpoint / Network / Web Application / Authentication]
- **Applicable Rules:** [List of rule IDs using this playbook]
- **Last Updated:** [YYYY-MM-DD]

## Alert Context
[Brief description of what alerts using this playbook detect and why they're suspicious]

## Initial Triage Questions
1. [Question about expected behavior]
2. [Question about user/system context]
3. [Question about timing]

## Investigation Steps

### Step 1: [Step Name]
**Objective:** [What you're looking for]

**Actions:**
- [Specific action to take]
- [Log query to run]
- [Artifact to examine]

**Expected Findings:**
- [What legitimate activity looks like]
- [What malicious activity looks like]

### Step 2: [Step Name]
...

## Evidence Collection
- [Required log sources]
- [Artifacts to preserve]
- [Commands to capture evidence]

## Escalation Criteria

### Escalate to Incident Response if:
- [Specific indicator 1]
- [Specific indicator 2]

### Mark as False Positive if:
- [Specific scenario 1]
- [Specific scenario 2]

## Response Actions (If True Positive)
1. [Immediate containment step]
2. [Evidence preservation step]
3. [Notification step]

## References
- [MITRE ATT&CK URLs]
- [Internal documentation]
- [External resources]
```

### Playbook Storage Location

**Directory Structure:**
```
Detections-Repository/
├── Playbooks/
│   ├── PLAYBOOK-001-Generic-Alert-Triage.md
│   ├── PLAYBOOK-005-LSASS-Memory-Dumping-Investigation.md
│   ├── PLAYBOOK-012-Credential-Access-from-Password-Stores.md
│   └── ...
├── Rules/
│   ├── [L1 Categories]/
│   │   ├── [L2 Use Cases]/
│   │   │   └── [L3 Detection Rules]
└── OPERATIONS-DOCUMENTATION.md
```

### Playbook Lifecycle Management

#### **Creation Process**

1. **Identify Need:**
   - New detection technique requires investigation guidance
   - Existing playbook doesn't cover specific scenario
   - High false positive rate requires detailed triage procedure

2. **Assign Playbook ID:**
   - Check existing playbook inventory
   - Select next available ID in appropriate range
   - Verify ID is not in use

3. **Develop Content:**
   - Document investigation steps
   - Define escalation criteria
   - Include evidence collection procedures
   - Add false positive scenarios

4. **Review and Approve:**
   - Peer review by senior analysts
   - Validation against real alerts
   - SOC team feedback

5. **Link to Detection Rules:**
   - Update detection rules with Playbook-ID
   - Update rule filenames if needed
   - Update playbook's "Applicable Rules" section

#### **Maintenance Process**

**Review Triggers:**
- Playbook used in actual investigation (feedback loop)
- New attack variations discovered
- Tool or log source changes
- False positive patterns identified
- Escalation criteria prove ineffective

**Update Procedure:**
1. Document needed changes
2. Update playbook content
3. Update "Last Updated" date
4. Communicate changes to SOC team
5. Update training materials if needed

#### **Deprecation Process**

**When to Deprecate:**
- Detection rules using this playbook are retired
- Playbook merged with another due to overlap
- Investigation procedure no longer applicable

**Deprecation Steps:**
1. Mark playbook as **DEPRECATED** in title
2. Add deprecation notice with reason and replacement playbook
3. Update all linked rules to new Playbook-ID
4. Move to `Playbooks/Deprecated/` folder
5. Keep for historical reference (do not delete)

### Playbook Inventory Management

**Maintain a Playbook Index:**

Create `Playbooks/PLAYBOOK-INDEX.md` to track all playbooks:

```markdown
# Triage Playbook Index

| Playbook ID | Name | Detection Scope | Related MITRE | Rule Count | Last Updated |
|-------------|------|-----------------|---------------|------------|--------------|
| 001 | Generic Alert Triage | All | Multiple | N/A | 2025-01-15 |
| 005 | LSASS Memory Dumping | Endpoint | T1003.001 | 12 | 2025-01-10 |
| 012 | Credential from Password Stores | Endpoint | T1555 | 8 | 2025-01-05 |
| ... | ... | ... | ... | ... | ... |
```

**Benefits:**
- Quick reference for playbook assignment
- Identify coverage gaps
- Track playbook usage
- Support audit and compliance needs

### Multi-Rule Playbook Usage Examples

**Example 1: Shared Playbook Across Similar Techniques**

```
PLAYBOOK-005-LSASS-Memory-Dumping-Investigation.md

Linked Rules:
- CRA-006-005-0020-Dump LSASS.exe Memory using ProcDump.yml
- CRA-006-005-0021-Dump LSASS.exe Memory using comsvcs.dll.yml
- CRA-006-005-0022-Dump LSASS.exe Memory using NanoDump.yml
- CRA-006-005-0023-Dump LSASS.exe Memory using Windows Task Manager.yml
- CRA-006-005-0025-Dump LSASS.exe Memory using Out-Minidump.ps1.yml
```

**Example 2: Technique-Specific Playbook**

```
PLAYBOOK-042-Kerberoasting-Investigation.md

Linked Rules:
- CRA-007-042-0001-Extract all accounts using setspn.yml
- CRA-007-042-0002-Request A Ticket via PowerShell.yml
- CRA-007-042-0003-Request All Tickets via PowerShell.yml
- CRA-007-042-0004-Kerberoasting Using Rubeus.yml
```

### Cross-Reference in Detection Rules

When creating or updating a detection rule, reference the playbook clearly:

```yaml
title: CRA-006-005-0020-Dump LSASS.exe Memory using ProcDump
id: CRA-006-005-0020
description: Detects usage of ProcDump to dump LSASS memory for credential extraction
# ... other fields ...
# Investigation Guidance: See PLAYBOOK-005-LSASS-Memory-Dumping-Investigation.md
```

---

## Detection Scope Indicators

### Overview

The detection scope indicator is a critical component of the L3 naming convention that identifies the primary telemetry source for each detection rule. This single-letter code enables rapid identification of data dependencies, facilitates coverage analysis, and supports efficient alert routing.

### Scope Categories

#### **E - Endpoint Detection**

**Definition:** Detections that rely on host-based telemetry from endpoints (workstations, servers, virtual machines).

**Primary Data Sources:**
- Windows Event Logs (Security, System, Application)
- Microsoft-Windows-Sysmon/Operational
- Microsoft-Windows-PowerShell/Operational
- Linux logs (/var/log/auth.log, /var/log/syslog)
- VMware ESXi logs (/var/log/shell.log, /var/log/hostd.log)

**Detection Examples:**
- Process execution (wmic.exe, powershell.exe)
- File creation or modification
- Registry key changes
- Service installation
- Scheduled task creation
- Local user/group modifications
- Script execution
- Named pipe creation

**When to Use:**
- Detection logic focuses on process behavior
- File system or registry artifacts are key indicators
- Local system configuration changes are detected
- Host-based persistence mechanisms are targeted

#### **N - Network Detection**

**Definition:** Detections that rely on network traffic metadata, flow data, or packet-level analysis.

**Primary Data Sources:**
- Palo Alto Firewall logs
- Fortinet FortiGate logs
- Network flow data (NetFlow, sFlow)
- IDS/IPS alerts and logs
- Sysmon Event ID 3 (when focused on network patterns)
- Network connection metadata

**Detection Examples:**
- Suspicious outbound connections (C2 beaconing)
- Port scanning or reconnaissance
- Lateral movement via network protocols
- Data exfiltration via unusual protocols
- DNS tunneling
- Traffic to known malicious IPs/domains
- Unusual protocol usage
- Network-based brute force attacks

**When to Use:**
- Detection relies on traffic patterns or flow metadata
- Source/destination IPs, ports, or protocols are primary indicators
- Network behavior is the focus (not the process initiating it)
- Firewall or IDS/IPS telemetry is the primary source

#### **W - Web Application Detection**

**Definition:** Detections that rely on web proxy logs, HTTP/HTTPS traffic analysis, or application-layer protocols.

**Primary Data Sources:**
- Zscaler Internet Access logs
- Web proxy logs
- HTTP/HTTPS traffic inspection
- URL filtering logs
- DLP policy events
- Cloud application logs

**Detection Examples:**
- Malicious URL access
- Web exploitation attempts (SQL injection, XSS)
- Command and control via HTTP/HTTPS
- Data exfiltration through web channels
- Malicious file downloads
- Web shell access
- Cloud application abuse
- Phishing site access
- Drive-by download attempts

**When to Use:**
- Detection focuses on URLs, domains, or HTTP methods
- Web content filtering or inspection is required
- Application-layer (Layer 7) analysis is needed
- Cloud application activity is monitored

#### **A - Authentication Detection**

**Definition:** Detections that rely on authentication events, credential validation, or identity management logs.

**Primary Data Sources:**
- Active Directory logs (Kerberos, NTLM events)
- Windows Security Event Log (4624, 4625, 4768, 4769, 4776)
- VPN logs (Pulse Secure)
- PAM logs (Arcon PAM)
- SSO/SAML authentication logs
- RADIUS/802.1X logs (wireless authentication)

**Detection Examples:**
- Brute force attacks (multiple failed logins)
- Pass-the-hash / Pass-the-ticket
- Kerberoasting
- Golden/Silver ticket usage
- Credential stuffing
- Unusual login patterns (geography, time)
- Privileged account abuse
- VPN authentication anomalies
- MFA bypass attempts

**When to Use:**
- Detection focuses on login events or authentication failures
- Kerberos or NTLM protocol analysis is required
- Credential validation events are primary indicators
- Session establishment is the focus
- Even if event is in Windows Security log, if it's authentication-focused, use **A**

### Scope Selection Decision Tree

```
START: What is the PRIMARY telemetry source for this detection?

├─ Does it detect authentication/login events?
│  ├─ YES → Use Scope: A (Authentication)
│  └─ NO → Continue
│
├─ Does it analyze HTTP/HTTPS traffic or web content?
│  ├─ YES → Use Scope: W (Web Application)
│  └─ NO → Continue
│
├─ Does it analyze network traffic patterns or connections?
│  ├─ YES → Use Scope: N (Network)
│  └─ NO → Continue
│
└─ Does it analyze host-based events (process, file, registry)?
   └─ YES → Use Scope: E (Endpoint)
```

### Multi-Source Detections

**Challenge:** Some detections may use multiple telemetry sources.

**Resolution Strategy:**
1. Identify the **primary** or **most critical** data source
2. Ask: "If I only had one log source, which would make this detection possible?"
3. Consider the detection's **intent**:
   - Detecting malicious process? → **E**
   - Detecting authentication abuse? → **A**
   - Detecting suspicious connection? → **E** or **N** (context-dependent)
   - Detecting web exploitation? → **W**

**Examples:**

| Detection | Scope | Rationale |
|-----------|-------|-----------|
| PowerShell downloading from malicious URL | **E** | Focus is on PowerShell process behavior, not the URL itself |
| Unusual process making outbound connection | **E** | Focus is on abnormal process behavior |
| Connection to known C2 IP address | **N** | Focus is on network connection to bad IP |
| Failed RDP login followed by successful login | **A** | Focus is on authentication pattern |
| SMB lateral movement with admin credentials | **A** | Focus is on credential usage (even though network-based) |
| Web shell HTTP POST requests | **W** | Focus is on web traffic pattern |

### Strategic Benefits of Scope Indicators

**1. Coverage Gap Analysis:**
- Quickly identify which detection categories have limited coverage in specific scopes
- Example: "We have many endpoint detections for lateral movement, but few network-based ones"

**2. Data Source Dependency Mapping:**
- Understand which detections fail if a log source becomes unavailable
- Prioritize log source reliability based on detection dependencies

**3. Alert Routing and Assignment:**
- Route alerts to specialized teams based on scope
  - Endpoint alerts → Endpoint security team
  - Network alerts → Network security team
  - Authentication alerts → Identity & Access Management team
  - Web alerts → Cloud security / Web security team

**4. Investigation Efficiency:**
- Analysts immediately know which tools and data sources to access
- Reduces context switching during investigations

**5. Detection Engineering Metrics:**
- Track detection development by scope
- Measure maturity across different telemetry domains

**6. Platform-Specific Tuning:**
- Optimize SIEM correlation rules based on scope grouping
- Deploy scope-specific detection logic to appropriate sensors/collectors

---

## Rule Structure and Standards

### Sigma Rule Format

All detection rules follow the Sigma standard format. Each rule must contain the following sections:

```yaml
title: [L3 Rule Identifier]-[Descriptive Name]
id: [lowercase-rule-identifier]
status: [experimental|test|stable]
description: [Clear description of what the rule detects and why it matters]
references:
    - [MITRE ATT&CK URL]
    - [Additional reference URLs]
author: HexaPrime Detection Team
date: YYYY/MM/DD
tags:
    - attack.[MITRE-Technique-ID]
    - attack.[tactic-name]
logsource:
    product: [product-name]
    category: [log-category]
detection:
    selection:
        [detection-logic]
    condition: [detection-condition]
    timeframe: [optional-timeframe]
falsepositives:
    - [Legitimate activity that may trigger]
    - [Business processes that generate similar patterns]
level: [low|medium|high|critical]
```

### Mandatory Fields

#### **title**
- Must start with the L3 rule identifier
- Followed by descriptive name
- Clear and concise
- Example: `EXE-004-E-000-0001-wmic.exe Process Call Create Execution`

#### **id**
- Unique identifier in lowercase
- Matches filename structure
- Example: `exe-004-e-000-0001`

#### **status**
- `experimental`: Newly created, needs validation
- `test`: Under testing, may need refinement
- `stable`: Validated and production-ready

#### **description**
- Explains what attack behavior the rule detects
- Why this detection matters
- Context on attacker techniques

#### **references**
- Always include MITRE ATT&CK technique URL
- Additional sources: LOLBAS project, security blogs, vendor advisories
- Atomic Red Team test references if applicable

#### **author**
- Default: `HexaPrime Detection Team`
- Individual names can be added for attribution

#### **date**
- Rule creation date
- Format: `YYYY/MM/DD`

#### **tags**
- MITRE ATT&CK technique IDs (e.g., `attack.T1047`)
- MITRE ATT&CK tactic names (e.g., `attack.execution`, `attack.credential_access`)

#### **logsource**
- **Critical**: Must map to available data sources
- **product**: Must be a log source currently ingested
- **category**: Must represent event type being collected
- See "Available Log Sources" section for valid values

#### **detection**
- **selection**: Field matching logic
- **condition**: Boolean logic combining selections
- **timeframe**: For correlation rules (e.g., `5m`, `1h`)

#### **falsepositives**
- List legitimate activities that may trigger the rule
- Administrative tools
- Business processes
- Helps analysts triage alerts

#### **level**
- `low`: Informational, low impact
- `medium`: Moderate concern, warrants investigation
- `high`: Significant threat indicator
- `critical`: Severe threat, immediate response required

---

## Available Log Sources and Data Sources

### Critical Constraint
**ALL DETECTION RULES MUST TARGET ONLY THE DATA SOURCES ACTIVELY COLLECTED AND INGESTED.**

Rules targeting unavailable log sources cannot trigger alerts and provide no detection value.

### Log Source Products

The following products and platforms are actively ingested:

#### **Network Security**
- **Palo Alto Firewall**
  - Network traffic flow
  - Allow/block decisions
  - Threat prevention logs
  - Malware metadata
  - Firewall admin authentication
  - Policy/config changes

- **Fortinet FortiGate (FortiOS)**
  - Network traffic flow
  - Session creation/teardown
  - Threat prevention logs
  - Firewall admin authentication
  - Policy/config changes

- **Zscaler Internet Access**
  - URL requests (full URL, domain, path)
  - HTTP methods and response codes
  - Web content filtering decisions
  - SSL inspection outcomes
  - DLP policy matches
  - Cloud app activity
  - User authentication events
  - Proxy/web access logs

#### **Secure Access**
- **Pulse Secure VPN**
  - VPN login success/failure
  - MFA/OTP events
  - Session creation/termination
  - Virtual IP assignments
  - SSL tunnel establishment
  - Certificate events
  - Session metadata (duration, source IP)

#### **Windows Servers**
- **Windows Event Logs (Security, System, Application)**
- **Microsoft-Windows-Sysmon/Operational**
- **Microsoft-Windows-PowerShell/Operational**
- **TerminalServices-RemoteConnectionManager/Operational**

Key Events:
- Process creation (4688, Sysmon 1)
- Network connections (5156, 5157, Sysmon 3)
- Authentication (4624, 4625, 4648)
- User/group modifications (4720, 4728, 4732, 4735, 4738)
- Scheduled tasks (4698)
- Service creation (4697)
- Registry modifications (Sysmon 12, 13)
- File creation (Sysmon 11)
- Named pipes (Sysmon 17)
- PowerShell script blocks (4104)

#### **Linux Servers**
- **/var/log/auth.log** (authentication)
- **/var/log/syslog** (system events)
- **Command execution logs** (sudo, bash history)
- **Process execution**
- **Network connections**
- **File creation**
- **SSH/console login sessions**

#### **Active Directory**
- **Windows Event Logs on Domain Controllers**

Key Events:
- Kerberos authentication (4768, 4769, 4770, 4771)
- NTLM authentication (4776)
- Failed logons (4625)
- Explicit credentials (4648)
- Domain user creation (4720)
- Domain user modification (4738)
- Password changes/resets (4723, 4724, 4740)
- Group membership changes (4728, 4729, 4732, 4733, 4756, 4757)
- User rights assignments (4704)

#### **Privileged Access Management**
- **Arcon PAM**
  - Syslog feed (authentication, account changes, admin events)
  - Session logs (privileged session start/stop)
  - User activity logs (machine details, actions, session IDs)

#### **Virtualization**
- **VMware ESXi**
  - /var/log/auth.log (SSH/Shell authentication)
  - /var/log/shell.log (ESXi shell commands)
  - /var/log/hostd.log (management tasks/API calls)
  - /var/log/vmkernel.log (network activity, system events)
  - /var/log/vpxa.log (vCenter agent activity)
  - /var/log/rhttpproxy.log (HTTP management connections)
  - /var/log/sysboot.log (startup/boot events)

#### **Wireless Infrastructure**
- **Wi-Fi Controllers/Access Points**
  - Controller admin authentication
  - 802.1X/WPA-Enterprise authentication (RADIUS/AAA logs)
  - WIDS/WIPS alerts (rogue AP, evil twin, deauth floods)
  - RF attack detection
  - Configuration changes
  - CLI/API command execution

#### **Network Switches**
- Switch configuration changes
- ACL/policy rule modifications
- CLI command execution

### Data Source Codes (DC)

Each data source code represents a specific type of telemetry:

| Code | Data Source Name | Description |
|------|------------------|-------------|
| DC0001 | Scheduled Job Creation | Detection of scheduled task/cron job creation |
| DC0002 | User Account Authentication | Login attempts (success/failure), authentication events |
| DC0005 | Scheduled Job Metadata | Scheduled task details (name, timing, command, triggers) |
| DC0010 | User Account Modification | Changes to user account attributes, permissions, status |
| DC0014 | User Account Creation | New user account creation events |
| DC0029 | Script Execution | PowerShell, bash, shell script execution |
| DC0032 | Process Creation/Execution | New process spawning, process metadata |
| DC0034 | Process Metadata | Process details (hashes, command line, image path) |
| DC0038 | Application Log Content | Application-specific logs (DLP, alerts, app events) |
| DC0039 | File Creation | New file creation events |
| DC0044 | Firewall Enumeration | Firewall config queries, enumeration commands |
| DC0048 | Named Pipe Metadata | Named pipe creation/connection |
| DC0051 | Firewall Rule Modification | Firewall rule changes |
| DC0056 | Windows Registry Key Creation | New registry key creation |
| DC0060 | Service Creation | New Windows service installation |
| DC0063 | Windows Registry Key Modification | Registry value/key modifications |
| DC0064 | Command Execution | Command-line execution (cmd, sudo, etc.) |
| DC0067 | Logon Session Creation | User session start (local, remote, VPN, SSH) |
| DC0078 | Network Traffic Flow | Network connection metadata (IPs, ports, bytes, protocols) |
| DC0082 | Network Connection Creation | TCP/UDP connection establishment |
| DC0084 | Active Directory Credential Request | Kerberos TGT/TGS requests |
| DC0085 | Network Traffic Content | HTTP requests, URLs, payloads, application protocols |
| DC0088 | Logon Session Metadata | Session details (source IP, auth method, duration) |
| DC0094 | Group Modification | Group membership changes |
| DC0102 | Network Share Access | SMB/CIFS share access events |
| DC0104 | Response Content | HTTP response codes, headers |
| DC0106 | Response Metadata | Response size, latency, resolved IPs |

### Sigma Logsource Mapping

When writing rules, the `logsource` field must map to available products and categories:

#### **Windows Servers**
```yaml
# Process creation
logsource:
    product: windows
    category: process_creation

# Network connections
logsource:
    product: windows
    category: network_connection

# Authentication
logsource:
    product: windows
    category: security

# PowerShell
logsource:
    product: windows
    category: powershell

# Registry modifications
logsource:
    product: windows
    category: registry_set

# File creation
logsource:
    product: windows
    category: file_event

# Service creation
logsource:
    product: windows
    category: service_installation
```

#### **Linux Servers**
```yaml
# Process execution
logsource:
    product: linux
    category: process_creation

# Authentication
logsource:
    product: linux
    category: auth

# File creation
logsource:
    product: linux
    category: file_event

# Network connections
logsource:
    product: linux
    category: network_connection
```

#### **Network Security**
```yaml
# Firewall traffic
logsource:
    product: firewall
    category: traffic

# Web proxy
logsource:
    product: proxy
    category: web

# Malware/threat detection
logsource:
    product: firewall
    category: threat
```

#### **Active Directory**
```yaml
# Domain controller events
logsource:
    product: windows
    category: security
    service: active_directory
```

---

## Triage Playbook Integration

### Overview

Triage playbooks are investigation runbooks that guide analysts through alert investigation, evidence collection, and escalation decisions. The Playbook-ID in the rule naming convention creates a direct link between detection rules and their corresponding investigation procedures.

### Purpose and Benefits

**Purpose:**
- Provide step-by-step investigation procedures for analysts responding to alerts
- Standardize investigation approaches across the SOC team
- Document evidence collection requirements and escalation criteria
- Reduce cognitive load during high-pressure incident response

**Benefits:**
- **Faster Triage**: Analysts immediately know which runbook to follow when an alert fires
- **Consistency**: Uniform investigation procedures across similar alerts and different analysts
- **Reduced MTTT**: Mean Time To Triage decreases with clear guidance
- **Better Documentation**: Standardized evidence collection improves case documentation
- **Training Aid**: New analysts can learn investigation procedures from playbooks
- **Quality Assurance**: Escalation criteria ensure appropriate handling of true positives

### Playbook ID Assignment

**ID Ranges:**
- `000`: Default placeholder - no specific playbook assigned yet
- `001-999`: Specific triage playbook references

**Assignment Strategy:**
- Multiple rules can share the same playbook if investigation procedures are identical
- Rules detecting the same technique with different methods often share playbooks
- Group rules by investigation approach rather than detection method

**Examples:**

| Playbook ID | Investigation Focus | Example Rules |
|-------------|---------------------|---------------|
| 000 | No playbook assigned | Newly created rules pending playbook development |
| 005 | LSASS Memory Dumping Investigation | All LSASS dump detection variants (ProcDump, comsvcs, Task Manager) |
| 012 | Credential Access from Password Stores | Browser credential theft, Credential Manager access, password file reads |
| 023 | WMI Remote Execution Investigation | WMI process creation, WMI service manipulation, WMI event subscriptions |

### Playbook Development Workflow

**When to Create a New Playbook:**
1. New attack technique requires unique investigation steps
2. Existing playbooks don't cover the evidence types needed
3. Escalation criteria differ significantly from similar techniques
4. Investigation requires specialized tools or access

**When to Reuse Existing Playbook:**
1. Investigation steps are identical to another technique
2. Evidence sources are the same
3. Escalation criteria align with existing playbook
4. Only detection method differs, not investigation approach

### Playbook Content Standards

Each triage playbook should include:

**1. Alert Overview**
- What the detection rule identifies
- Why this activity is suspicious
- Common attack scenarios

**2. Initial Triage Questions**
- Is the user/system expected to perform this action?
- Is this part of scheduled maintenance or known business process?
- Does timing align with user's normal activity patterns?

**3. Evidence Collection Steps**
- Required log sources to query
- Specific events/artifacts to collect
- Timeframes for investigation (before/after alert)
- Related indicators to pivot on

**4. Contextual Analysis**
- Parent/child processes to examine
- Network connections to investigate
- File system artifacts to review
- Registry changes to analyze
- User behavior patterns to assess

**5. Escalation Criteria**
- Clear true positive indicators
- Severity escalation triggers
- When to engage incident response
- When to classify as false positive

**6. Response Actions**
- Immediate containment steps if true positive
- Evidence preservation procedures
- Stakeholder notification requirements
- Ticketing and documentation standards

### Integration with SIEM/SOAR

**Playbook ID in Alerting:**
- Include Playbook-ID in alert metadata
- Link directly to playbook documentation from alert
- Populate investigation templates based on Playbook-ID
- Track playbook usage and effectiveness metrics

**Automation Opportunities:**
- Auto-populate investigation checklists
- Trigger evidence collection scripts
- Route alerts to specialized teams based on playbook
- Generate investigation reports with playbook-specific sections

### Playbook Maintenance

**Review Triggers:**
- New attack variations discovered
- Investigation steps prove ineffective
- False positive patterns identified
- Tool or log source changes

**Update Process:**
1. Document needed changes
2. Update playbook content
3. Communicate changes to SOC team
4. Update training materials
5. Track effectiveness post-change

### Playbook ID Updates to Rules

**When to Update Rule Playbook-ID:**
- New playbook created for existing technique
- Rules consolidated to shared playbook
- Playbook scope changes (split or merge)

**Update Process:**
1. Identify all rules requiring update
2. Update filename with new Playbook-ID
3. Update `id` field in YAML to match
4. Commit changes with clear description
5. Update playbook mapping documentation

---

## Rule Creation Process

### Step 1: Identify Detection Opportunity

**Sources for new detection ideas:**
- MITRE ATT&CK technique coverage gaps
- Threat intelligence reports
- Incident response findings
- Red team/purple team exercises
- Security research and blogs
- Atomic Red Team tests
- Sigma public rule repositories (adapt to our environment)

**Validation questions:**
- Do we have the necessary log sources to detect this?
- Which data sources (DC codes) provide visibility?
- What specific log events contain the indicators?

### Step 2: Determine Rule Placement

**L1 Category:**
- Which MITRE ATT&CK tactic does this technique belong to?
- Select appropriate L1 category (EXE, CRA, DFE, etc.)

**L2 Use Case:**
- Does an existing L2 use case cover this technique?
  - **Yes**: Place rule in existing L2 folder
  - **No**: Create new L2 use case folder

**L2 Use Case Creation (if needed):**
- Assign next sequential L2 number for the L1 category
- Create folder: `[L1-CODE]-[L2-Number]-[Use Case Name]`
- Example: `CRA-008-Stolen Credential Reuse`

### Step 3: Assign Rule Number and Playbook ID

**Assign Rule Number:**
- Identify highest existing rule number in the L2 folder
- Assign next sequential number
- Example: If highest is `0015`, new rule is `0016`

**Determine Playbook ID:**
- Check if a triage playbook exists for this technique
  - **Yes**: Use the existing playbook ID
  - **No**: Use `000` as placeholder

**Complete Rule Identifier:**
- Format: `[L1-CODE]-[L2-Number]-[Playbook-ID]-[Rule-Number]`
- Example: `CRA-006-000-0016` (no playbook assigned)
- Example: `CRA-006-003-0016` (uses playbook 003)
- Example: `CRA-001-005-0008` (uses playbook 005)
- Example: `CNC-002-000-0023` (no playbook assigned)

**Determine Detection Scope (for metadata/documentation):**
While not part of the filename, identify the primary telemetry source for categorization:
- **Endpoint**: Windows/Linux event logs, Sysmon, process/file/registry events
- **Network**: Firewall, network flow, IDS/IPS, packet data
- **Web Application**: Proxy logs, web gateway, HTTP/URL events
- **Authentication**: Login events, Kerberos, NTLM, VPN, AD authentication

### Step 4: Write Detection Logic

**Research the technique:**
- Study MITRE ATT&CK technique page
- Review Atomic Red Team tests
- Analyze attack tool behavior
- Understand legitimate use cases

**Identify indicators:**
- Process names, command-line patterns
- Event IDs, log fields
- File paths, registry keys
- Network connections, URLs
- User behaviors, timing patterns

**Write Sigma detection logic:**
```yaml
detection:
    selection:
        [field_name]: [value]
        [field_name]|[modifier]: [value]
    condition: selection
```

**Common modifiers:**
- `contains`: Field contains substring
- `endswith`: Field ends with value
- `startswith`: Field starts with value
- `all`: All values must match
- `re`: Regular expression match

### Step 5: Map to Log Sources

**Determine logsource:**
- Which product generates the logs? (Windows, Linux, firewall, etc.)
- Which log category contains the events? (process_creation, security, etc.)

**Validate data availability:**
- Confirm the log source is actively ingested
- Verify the specific event types are collected
- Check that required fields are available

### Step 6: Define False Positives

**Consider legitimate scenarios:**
- Administrative tools and scripts
- Software deployment processes
- Legitimate business applications
- Scheduled maintenance tasks
- Developer/IT workflows

**Document in falsepositives section:**
```yaml
falsepositives:
    - System administrators using management tools
    - Automated patch deployment
    - Security scanning tools
```

### Step 7: Set Severity Level

**Guidelines:**
- **Critical**: Active exploit, credential theft, data exfiltration
- **High**: Suspicious privilege escalation, defense evasion, lateral movement
- **Medium**: Reconnaissance, discovery, potentially suspicious activity
- **Low**: Informational, baseline deviations, low-risk behaviors

### Step 8: Create Rule File

**File creation:**
- Create YAML file in appropriate L2 folder
- Filename: `[L1-CODE]-[L2-Number]-[Playbook-ID]-[Rule-Number]-[Descriptive-Name].yml`
- Validate YAML syntax
- Ensure all mandatory fields are present
- Verify consistency:
  - L1 code is UPPERCASE
  - Playbook-ID in filename matches the ID in the rule
  - Rule number is sequential and unique within L2 folder
  - Rule ID in YAML matches filename structure

### Step 9: Test and Validate

**Testing methods:**
- Execute Atomic Red Team test (if available)
- Simulate the technique in lab environment
- Review historical logs for matches
- Validate detection logic triggers correctly
- Check for excessive false positives

**Refinement:**
- Adjust detection logic to reduce noise
- Add exclusions for known benign activity
- Tune field values and conditions
- Update status from `experimental` to `test` after initial validation

### Step 10: Document and Commit

**Git workflow:**
- Create descriptive commit message
- Reference MITRE technique ID
- Note new L2 creation if applicable
- Push to repository

---

## Rule Review and Improvement Process

### Review Triggers

**Periodic review:**
- Quarterly rule effectiveness assessment
- Coverage gap analysis against MITRE ATT&CK
- False positive rate evaluation

**Event-driven review:**
- After incident response (missed detections)
- New threat intelligence on techniques
- Log source changes or additions
- MITRE ATT&CK framework updates

### Review Criteria

#### **1. Detection Logic Accuracy**
- Does the rule accurately detect the intended technique?
- Are there bypasses or evasion opportunities?
- Are field names and values correct?
- Does the condition logic work as intended?

#### **2. False Positive Rate**
- Is the rule generating excessive false positives?
- Can we add filters to reduce noise?
- Are documented false positives comprehensive?

#### **3. Log Source Mapping**
- Is the logsource still valid and actively ingested?
- Do we have better/additional log sources now?
- Are we using the optimal event types?

#### **4. Coverage Completeness**
- Does the rule cover all variations of the technique?
- Are there platform-specific versions needed (Windows/Linux)?
- Can we detect different attacker tools using this technique?

#### **5. MITRE Alignment**
- Are MITRE tags accurate and current?
- Have MITRE techniques been updated or deprecated?
- Are sub-technique mappings correct?

#### **6. Documentation Quality**
- Is the description clear and accurate?
- Are references current and accessible?
- Are false positives well-documented?

### Improvement Process

#### **Step 1: Identify Rules for Review**
- Select L1 category or L2 use case
- Pull all rules in scope
- Prioritize based on:
  - High false positive rates
  - Zero detections (potential gap)
  - Recent threat intelligence updates
  - New log source availability

#### **Step 2: Analyze Rule Performance**
- Review alert statistics (true/false positive ratio)
- Examine recent triggered alerts
- Validate against known attack patterns
- Test against Atomic Red Team scenarios

#### **Step 3: Identify Improvements**

**Detection logic enhancements:**
- Add additional selection criteria
- Refine field matching (use more specific modifiers)
- Add correlation logic (timeframes, aggregations)
- Create multiple variants for different platforms

**False positive reduction:**
- Add filter conditions to exclude benign activity
- Incorporate whitelist logic for known safe processes/paths
- Refine command-line pattern matching

**Coverage expansion:**
- Create additional rules for technique variations
- Add platform-specific rules
- Cover different attacker tools

**Log source optimization:**
- Switch to better data sources if available
- Leverage new log fields
- Improve event type targeting

#### **Step 4: Update Rule**
- Modify YAML file with improvements
- Update date field to reflect modification
- Consider updating status if moving to `stable`
- Add comments in Git commit explaining changes

#### **Step 5: Re-test**
- Validate improved logic triggers correctly
- Confirm false positives are reduced
- Test against attack simulations
- Monitor initial production deployment

#### **Step 6: Document Changes**
- Update rule description if detection scope changed
- Revise false positives section
- Add references if new research informed changes
- Commit with detailed change notes

### Coverage Gap Analysis

**Process:**
1. Map existing rules to MITRE ATT&CK Navigator
2. Identify techniques without detection rules
3. Cross-reference with available log sources
4. Prioritize based on:
   - Threat prevalence
   - Organizational risk
   - Data source availability
   - Detection feasibility
5. Create new rules for high-priority gaps

---

## Quality Standards and Best Practices

### Detection Quality Principles

#### **1. Precision over Noise**
- Better to have fewer high-fidelity alerts than alert fatigue
- Tune rules to minimize false positives
- Document expected benign triggers

#### **2. Context over Volume**
- Include sufficient context in detection logic
- Use field combinations, not single indicators
- Consider parent processes, user context, timing

#### **3. Resilience to Evasion**
- Avoid brittle exact-string matching when possible
- Use case-insensitive matching where appropriate
- Consider obfuscation techniques (base64, encoding)

#### **4. Comprehensive Coverage**
- Cover multiple variations of the same technique
- Create platform-specific versions (Windows/Linux/ESXi)
- Detect different attacker tools implementing the technique

### Rule Writing Best Practices

#### **Command-line Detection**
- Use `contains|all` for multiple required keywords
- Avoid overly specific paths that can be bypassed
- Consider command-line obfuscation (carets, quotes, variables)
- Match on both full paths and base filenames

**Example:**
```yaml
selection:
    CommandLine|contains|all:
        - 'process'
        - 'call'
        - 'create'
    Image|endswith: '\wmic.exe'
```

#### **Process Hierarchy**
- Leverage parent-child process relationships
- Unusual parent processes are strong indicators
- Use `ParentImage` field when available

**Example:**
```yaml
selection:
    Image|endswith: '\powershell.exe'
    ParentImage|endswith: '\winword.exe'
```

#### **Time-based Correlation**
- Use `timeframe` for frequency-based detection
- Use aggregation for brute force, scanning, enumeration

**Example:**
```yaml
detection:
    selection:
        EventID: 4625
    condition: selection | count(TargetUserName) by IpAddress > 10
    timeframe: 5m
```

#### **Field Modifiers**
- `contains`: Substring match
- `endswith`: Suffix match (good for file paths)
- `startswith`: Prefix match
- `all`: All listed values must be present
- `re`: Regular expression (use sparingly, performance cost)

### Testing and Validation

#### **Pre-deployment Testing**
- Validate YAML syntax
- Test against Atomic Red Team scenarios
- Query historical logs for baseline matches
- Review with peer/senior analyst

#### **Production Monitoring**
- Monitor initial alert volume
- Triage first alerts for accuracy
- Collect false positive examples
- Iterate and refine as needed

### Documentation Standards

#### **Clear Descriptions**
- Explain the attack technique, not just the indicator
- Describe why this behavior is suspicious
- Provide context for analysts investigating alerts

**Good example:**
```yaml
description: Detects execution of wmic.exe with process call create commands which can be used by attackers to execute arbitrary commands remotely or locally
```

**Poor example:**
```yaml
description: Detects wmic process create
```

#### **Comprehensive References**
- Always include MITRE ATT&CK link
- Add vendor advisories, threat reports, or blogs
- Link to Atomic Red Team tests when available
- Reference LOLBAS project for Living-off-the-Land techniques

#### **Actionable False Positives**
- Describe specific legitimate activities
- Include context (who, what, when)
- Help analysts make triage decisions

**Good example:**
```yaml
falsepositives:
    - System administrators using WMIC for remote management
    - Automated software deployment tools (SCCM, PDQ Deploy)
    - IT asset inventory scanning tools
```

---

## Mapping Data Sources to Detection Capabilities

### Data Source to L1 Category Mapping

Understanding which log sources enable detection for each MITRE tactic:

| L1 Category | Primary Data Sources | Key Log Products |
|-------------|---------------------|------------------|
| REC - Reconnaissance | DC0078 (Network Traffic), DC0085 (Traffic Content) | Firewall, Zscaler |
| INA - Initial Access | DC0002 (Authentication), DC0085 (Web), DC0038 (App Logs) | Windows, AD, Firewall, Zscaler |
| EXE - Execution | DC0032 (Process), DC0064 (Commands), DC0029 (Scripts) | Windows, Linux, Sysmon |
| PER - Persistence | DC0001 (Sched Jobs), DC0060 (Services), DC0063 (Registry) | Windows, Linux, Sysmon |
| PRE - Privilege Escalation | DC0032 (Process), DC0010 (Account Mod), DC0088 (Session) | Windows, Linux, AD |
| DFE - Defence Evasion | DC0032 (Process), DC0063 (Registry), DC0039 (Files) | Windows, Sysmon, Linux |
| CRA - Credential Access | DC0002 (Auth), DC0084 (Cred Requests), DC0032 (Process) | Windows, AD, Sysmon |
| DIS - Discovery | DC0064 (Commands), DC0032 (Process) | Windows, Linux, Sysmon |
| LAT - Lateral Movement | DC0002 (Auth), DC0067 (Sessions), DC0082 (Connections) | Windows, AD, Network |
| COL - Collection | DC0039 (Files), DC0102 (Shares), DC0064 (Commands) | Windows, Linux, Sysmon |
| CNC - Command & Control | DC0082 (Connections), DC0078 (Traffic), DC0085 (Content) | Firewall, Zscaler, Sysmon |
| EXF - Exfiltration | DC0078 (Traffic), DC0085 (Content), DC0082 (Connections) | Firewall, Zscaler, Sysmon |
| IMP - Impact | DC0032 (Process), DC0064 (Commands), DC0039 (Files) | Windows, Linux, Sysmon |

### Platform Coverage

Ensuring comprehensive detection across all platforms:

| Platform | Available Logs | Detection Focus Areas |
|----------|---------------|----------------------|
| Windows Servers | Security, Sysmon, PowerShell, System | Execution, Persistence, Credential Access, Privilege Escalation |
| Linux Servers | Auth, Syslog, Commands, Process | Execution, Persistence, Discovery, Credential Access |
| Active Directory | DC Security Logs | Authentication, Lateral Movement, Credential Access |
| VMware ESXi | Shell logs, hostd, vmkernel | Execution, Discovery, Impact (virtualization attacks) |
| Network (Firewalls) | Traffic flow, threats | Initial Access, Command & Control, Exfiltration |
| Web Proxy (Zscaler) | URL, content, DLP | Initial Access, Command & Control, Exfiltration, Collection |
| VPN (Pulse Secure) | Authentication, sessions | Initial Access, Lateral Movement |
| PAM (Arcon) | Privileged sessions | Privilege Escalation, Lateral Movement |

---

## Continuous Improvement Cycle

### Monthly Activities
- Review new rules in `experimental` status for promotion to `test` or `stable`
- Analyze alert statistics for false positive trends
- Update MITRE coverage tracking

### Quarterly Activities
- Conduct comprehensive coverage gap analysis
- Review and update rules with high false positive rates
- Align with MITRE ATT&CK framework updates
- Incorporate threat intelligence and incident learnings

### Annual Activities
- Full repository audit and cleanup
- Archive deprecated or ineffective rules
- Document lessons learned and detection maturity progress
- Update process documentation

---

## Version Control and Change Management

### Git Workflow
- All rule changes must be committed to Git
- Descriptive commit messages required
- Include MITRE technique ID in commits
- Reference incident/ticket numbers when applicable

### Rule Lifecycle
1. **experimental**: Newly created, under initial testing
2. **test**: Field testing in production, refinement phase
3. **stable**: Validated, low false positive rate, production-ready

### Change Documentation
- Update rule `date` field on modifications
- Document reason for changes in Git commit
- Track major logic changes in rule comments if needed

---

## Appendix: Quick Reference

### L1 Category Quick Reference
| Code | Name | MITRE ID |
|------|------|----------|
| REC | Reconnaissance | TA0043 |
| INA | Initial Access | TA0001 |
| EXE | Execution | TA0002 |
| PER | Persistence | TA0003 |
| PRE | Privilege Escalation | TA0004 |
| DFE | Defence Evasion | TA0005 |
| CRA | Credential Access | TA0006 |
| DIS | Discovery | TA0007 |
| LAT | Lateral Movement | TA0008 |
| COL | Collection | TA0009 |
| CNC | Command & Control | TA0011 |
| EXF | Exfiltration | TA0010 |
| IMP | Impact | TA0040 |

### Common Sigma Logsource Values
```yaml
# Windows process creation
product: windows
category: process_creation

# Windows authentication
product: windows
category: security

# PowerShell execution
product: windows
category: powershell

# Linux process execution
product: linux
category: process_creation

# Firewall traffic
product: firewall
category: traffic

# Web proxy
product: proxy
category: web
```

### Rule Numbering Examples

**Basic Example (No Playbook):**
```
L1: CRA
L2: CRA-006-OS Credentials Dumping
L3: CRA-006-000-0041-Directory Services Restore Mode Password Reset.yml
ID: CRA-006-000-0041
(No playbook assigned - using 000)
```

**With Playbook Assignment:**
```
L1: CRA
L2: CRA-006-OS Credentials Dumping
L3: CRA-006-005-0041-Directory Services Restore Mode Password Reset.yml
ID: CRA-006-005-0041
(Linked to triage playbook 005)
```

**Additional Examples:**
```
L1: CRA
L2: CRA-001-Brute Force
L3: CRA-001-002-0001-Multiple Failed Logins Same Source.yml
ID: CRA-001-002-0001
(Playbook 002)

L1: CNC
L2: CNC-003-Command and Control Channels
L3: CNC-003-000-0015-Suspicious DNS Tunneling Activity.yml
ID: CNC-003-000-0015
(No playbook)

L1: INA
L2: INA-004-Web Application Exploitation
L3: INA-004-008-0003-SQL Injection in User Input.yml
ID: INA-004-008-0003
(Playbook 008)
```

---

**Document Version:** 1.0
**Last Updated:** 2025-12-18
**Maintained By:** HexaPrime Detection Team
