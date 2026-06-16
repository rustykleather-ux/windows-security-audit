# Windows Security Assessor

A Python-based Windows security assessment tool that performs host-level security auditing and generates professional HTML, JSON, and CSV reports.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

Windows Security Assessor is designed to help system administrators, IT professionals, and security teams quickly evaluate the security posture of Windows workstations and servers.

The tool performs automated security checks across operating system hardening, endpoint protection, patch management, identity controls, persistence mechanisms, and network exposure.

Results are presented in a weighted scoring model with remediation guidance and letter-grade ratings.

---

## Features

### Endpoint Protection

- Microsoft Defender Health
- Defender Real-Time Protection
- Defender Signature Age
- Defender ASR Rules
- PowerShell Security Settings

### System Hardening

- Windows Firewall
- User Account Control (UAC)
- Secure Boot
- TPM Status
- LSA Protection
- Credential Guard

### Patch Management

- Pending Windows Updates
- Last Installed Update Age

### Data Protection

- BitLocker Status
- Full Volume Encryption Coverage
- USB Storage Controls

### Identity & Access

- Local Administrators Audit
- Local User Audit
- Password Policy Review
- Failed Login Analysis

### Network Security

- RDP Configuration
- SMB Security Settings
- Listening Ports Review
- Network Share Discovery
- Share Permission Analysis

### Persistence & Threat Hunting

- Installed Software Inventory
- Scheduled Tasks Review
- Autorun Registry Analysis
- Startup Folder Review
- Windows Services Review

---

## Reporting

The tool generates:

- HTML Reports
- JSON Reports
- CSV Reports
- Console Summary Reports

Reports include:

- Weighted Security Scoring
- Letter Grades (A-F)
- Risk Ratings
- Remediation Guidance
- Executive Summary
- Security Categories
- Raw Audit Evidence

---

## Security Categories

| Category | Checks |
|-----------|---------|
| Endpoint Protection | Defender, ASR, Signatures, PowerShell |
| Patch Management | Windows Updates |
| Network Exposure | Firewall, SMB, RDP, Shares |
| Identity & Access | Users, Admins, Passwords |
| Data Protection | BitLocker, TPM, Secure Boot |
| Logging & Visibility | Event Logging |
| Persistence Review | Services, Tasks, Autoruns |

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/windows-security-assessor.git
cd windows-security-assessor
```

Verify Python:

```bash
python --version
```

Recommended:

```bash
python -m venv venv
venv\Scripts\activate
```

---

## Usage

Run a complete audit:

```bash
python windows_security_assessor.py
```

Generate HTML report only:

```bash
python windows_security_assessor.py --html
```

Generate JSON report only:

```bash
python windows_security_assessor.py --json
```

Generate CSV report only:

```bash
python windows_security_assessor.py --csv
```

Generate console summary:

```bash
python windows_security_assessor.py --summary
```

Specify custom output folder:

```bash
python windows_security_assessor.py --output C:\Reports
```

Run quietly:

```bash
python windows_security_assessor.py --quiet
```

---

## Example Output

```text
Overall Grade: B
Weighted Score: 84/100

FAIL (2)
- Defender ASR Rules
- BitLocker

REVIEW (4)
- RDP
- USB Storage
- Scheduled Tasks
- Share Permissions

PASS (21)
```

---

## Scoring

Security scores are weighted based on risk.

Example:

| Control | Weight |
|----------|---------|
| Firewall | 10 |
| Defender | 12 |
| BitLocker | 10 |
| Credential Guard | 10 |
| Scheduled Tasks | 6 |
| Startup Folders | 5 |

Final scores are converted into letter grades:

| Score | Grade |
|---------|---------|
| 90-100 | A |
| 80-89 | B |
| 70-79 | C |
| 60-69 | D |
| Below 60 | F |

---

## Recommended Use Cases

- Security Assessments
- System Hardening Reviews
- Cybersecurity Audits
- Incident Response Preparation
- Compliance Validation
- Threat Hunting Baselines

---

## Roadmap

### Version 2.0

- AppLocker Auditing
- WDAC Auditing
- LAPS Auditing
- Browser Security Auditing
- PDF Report Export
- Multi-System Scanning
- Centralized Dashboard
- Historical Trending

---

## Disclaimer

This tool is intended for defensive security auditing and system hardening purposes.

Review all findings before making production changes.

The author assumes no responsibility for system modifications resulting from report recommendations.

---

## License

MIT License