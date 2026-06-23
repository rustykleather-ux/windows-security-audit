import argparse
import csv
import ctypes
import html
from html import parser
import json
import platform
import subprocess
from datetime import datetime
from pathlib import Path






# ----------------------------
# Constants
# ----------------------------

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

if not Path(POWERSHELL).exists():
    POWERSHELL = "powershell"


CHECK_WEIGHTS = {
    "Threat Hunt - Remote Access Tools": 12,
    "Threat Hunt - Suspicious Processes": 12,
    "Threat Hunt - Persistence Indicators": 12,
    "Firewall": 10,
    "Microsoft Defender": 12,
    "Defender Signatures": 8,
    "BitLocker": 10,
    "BitLocker All Volumes": 10,
    "Windows Update": 10,
    "Windows Update Age": 10,
    "RDP": 8,
    "SMB": 8,
    "UAC": 8,
    "Secure Boot / TPM": 10,
    "Event Logging": 8,
    "Installed Software": 5,
    "Scheduled Tasks": 6,
    "Autorun Registry Keys": 6,
    "Startup Folders": 5,
    "Windows Services": 7,
    "Local Administrators": 7,
    "Local Users": 7,
    "Password Policy": 7,
    "Failed Logins": 6,
    "Network Shares": 6,
    "Share Permissions": 8,
    "LSA / Credential Guard": 10,
    "Defender ASR Rules": 10,
    "Listening Connections": 7,
    "PowerShell Security": 8,
    "USB Storage": 5,
    "Vulnerable Software Detection": 10,
    "Threat Hunt - Remote Access Tools": 12,
    "Threat Hunt - Suspicious Processes": 12,
    "Threat Hunt - Persistence Indicators": 12,
    "Threat Hunt - Network Connections": 15,
}

MITRE_MAPPINGS = {
    "Threat Hunt - Suspicious Processes": [
        ("T1059", "Command and Scripting Interpreter"),
        ("T1218", "Signed Binary Proxy Execution"),
        ("T1105", "Ingress Tool Transfer"),
    ],

    "Threat Hunt - Persistence Indicators": [
        ("T1053", "Scheduled Task/Job"),
        ("T1547", "Boot or Logon Autostart Execution"),
    ],

    "Threat Hunt - Remote Access Tools": [
        ("T1219", "Remote Access Software"),
    ],

    "Threat Hunt - Network Connections": [
        ("T1071", "Application Layer Protocol"),
        ("T1095", "Non-Application Layer Protocol"),
        ("T1105", "Ingress Tool Transfer"),
    ],

    "PowerShell Security": [
        ("T1059.001", "PowerShell"),
    ],

    "Listening Connections": [
        ("T1046", "Network Service Discovery"),
    ],

    "Scheduled Tasks": [
        ("T1053", "Scheduled Task/Job"),
    ],

    "Autorun Registry Keys": [
        ("T1547.001", "Registry Run Keys / Startup Folder"),
    ],

    "Startup Folders": [
        ("T1547.001", "Registry Run Keys / Startup Folder"),
    ],
}


REMEDIATION_GUIDANCE = {
    "Firewall": {
        "risk": "High",
        "why": "Disabled firewall profiles can expose local services to untrusted networks.",
        "fix": "Enable Domain, Private, and Public firewall profiles. In PowerShell: Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"
    },
    "Microsoft Defender": {
        "risk": "High",
        "why": "Disabled endpoint protection increases malware and ransomware risk.",
        "fix": "Enable Microsoft Defender Antivirus and real-time protection, or verify that another managed EDR/AV is active."
    },
    "Defender Signatures": {
        "risk": "Medium",
        "why": "Outdated signatures reduce Defender's ability to detect recent threats.",
        "fix": "Run Windows Update or Update-MpSignature. Confirm signature updates are managed by policy if this is a domain device."
    },
    "BitLocker": {
        "risk": "High",
        "why": "Unencrypted system drives can expose data if the device is lost, stolen, or removed from service.",
        "fix": "Enable BitLocker on the operating system drive and securely escrow the recovery key."
    },
    "BitLocker All Volumes": {
        "risk": "High",
        "why": "Secondary unencrypted volumes may contain sensitive data even when C: is protected.",
        "fix": "Enable BitLocker on all fixed data volumes or document why a volume is exempt."
    },
    "Windows Update": {
        "risk": "High",
        "why": "Pending security updates may leave known vulnerabilities exploitable.",
        "fix": "Install pending Windows updates and reboot if required. Verify WSUS, Intune, or update policy health."
    },
    "Windows Update Age": {
        "risk": "High",
        "why": "Systems that have not installed updates recently may be missing security patches.",
        "fix": "Install the latest cumulative update and confirm the device is checking in to its update management system."
    },
    "RDP": {
        "risk": "High",
        "why": "Exposed or weakly configured RDP is commonly abused for unauthorized access and ransomware.",
        "fix": "Disable RDP where not needed. If required, enable NLA, restrict firewall scope, and require VPN or strong conditional access."
    },
    "SMB": {
        "risk": "High",
        "why": "Legacy SMB and weak SMB settings can enable lateral movement and credential exposure.",
        "fix": "Disable SMBv1, disable insecure guest logons, and require SMB signing where practical."
    },
    "UAC": {
        "risk": "Medium",
        "why": "Weak UAC settings make privilege escalation and accidental administrative changes easier.",
        "fix": "Enable UAC, admin approval mode, and secure desktop prompts."
    },
    "Secure Boot / TPM": {
        "risk": "High",
        "why": "Secure Boot and TPM help protect boot integrity, BitLocker keys, and credential protections.",
        "fix": "Enable TPM and Secure Boot in firmware/UEFI where supported."
    },
    "Event Logging": {
        "risk": "Medium",
        "why": "Weak audit policy can leave gaps during incident response and forensic review.",
        "fix": "Enable success and failure auditing for logon, account logon, account management, policy change, and privilege use events."
    },
    "Installed Software": {
        "risk": "Medium",
        "why": "Remote access tools, outdated runtimes, and dual-use utilities can increase attack surface.",
        "fix": "Review flagged software, remove unapproved tools, and update or replace outdated applications."
    },
    "Scheduled Tasks": {
        "risk": "Medium",
        "why": "Scheduled tasks are a common persistence method for malware and unauthorized tools.",
        "fix": "Review flagged tasks, confirm the owner and command path, and remove unauthorized entries."
    },
    "Autorun Registry Keys": {
        "risk": "Medium",
        "why": "Autorun keys can launch programs at sign-in and are commonly used for persistence.",
        "fix": "Review flagged autorun entries, verify file paths and publishers, and remove unauthorized entries."
    },
    "Startup Folders": {
        "risk": "Medium",
        "why": "Startup folder items can silently launch programs when users sign in.",
        "fix": "Review startup folder contents and remove scripts, shortcuts, or executables that are not approved."
    },
    "Windows Services": {
        "risk": "Medium",
        "why": "Services running automatically can provide persistence or privilege escalation opportunities.",
        "fix": "Review flagged services, verify executable paths and publishers, and fix unquoted service paths."
    },
    "Local Administrators": {
        "risk": "High",
        "why": "Too many local administrators increases the chance of credential theft and lateral movement.",
        "fix": "Remove unnecessary local admins and manage privileged access through approved groups or LAPS/Windows LAPS."
    },
    "Local Users": {
        "risk": "Medium",
        "why": "Unexpected enabled local accounts can provide alternate access paths.",
        "fix": "Disable unused local accounts, ensure Guest is disabled, and require passwords for enabled accounts."
    },
    "Password Policy": {
        "risk": "Medium",
        "why": "Weak password and lockout policies increase brute-force and password guessing risk.",
        "fix": "Set a strong minimum password length and configure account lockout thresholds appropriate for the environment."
    },
    "Failed Logins": {
        "risk": "Medium",
        "why": "Repeated failed logons may indicate password guessing, stale services, or unauthorized access attempts.",
        "fix": "Review Event ID 4625 details, source IPs, usernames, and correlated successful logons."
    },
    "Network Shares": {
        "risk": "Medium",
        "why": "Unnecessary shares can expose sensitive data or broaden lateral movement paths.",
        "fix": "Remove unneeded shares and document business owners for required shares."
    },
    "Share Permissions": {
        "risk": "High",
        "why": "Broad share permissions such as Everyone or Guest can expose sensitive files.",
        "fix": "Remove Everyone, Guest, and Anonymous access. Limit share permissions to approved groups using least privilege."
    },
    "LSA / Credential Guard": {
        "risk": "High",
        "why": "Without credential protections, attackers may more easily dump or reuse credentials from memory.",
        "fix": "Enable LSA protection and Credential Guard where supported. Validate compatibility before broad deployment."
    },
    "Defender ASR Rules": {
        "risk": "High",
        "why": "ASR rules block common exploit and malware behaviors beyond basic antivirus detection.",
        "fix": "Enable recommended ASR rules in audit mode first, review impact, then enforce approved rules through Intune, Group Policy, or security baseline."
    },
    "Listening Connections": {
        "risk": "Medium",
        "why": "Unexpected listening ports can expose services to the network.",
        "fix": "Review flagged ports, stop unnecessary services, and restrict exposure with Windows Firewall."
    },
    "PowerShell Security": {
        "risk": "Medium",
        "why": "PowerShell is commonly used in attacks; weak logging reduces detection and investigation capability.",
        "fix": "Enable Script Block Logging, Module Logging, Transcription where appropriate, and disable PowerShell v2."
    },
    "USB Storage": {
        "risk": "Low",
        "why": "USB storage can increase data loss and malware introduction risk.",
        "fix": "Use removable storage restrictions where required by policy, especially for sensitive workstations."
    },
    "Vulnerable Software Detection": {
        "risk": "High",
        "why": "Unsupported or commonly outdated software can expose known vulnerabilities that attackers routinely exploit.",
        "fix": "Upgrade, patch, or remove flagged software. Validate exceptions with business owners and document compensating controls."
       
    },
    "Threat Hunt - Remote Access Tools": {
        "risk": "High",
        "why": "The presence of remote access tools can indicate unauthorized access or persistence.",
        "fix": "Investigate the source and purpose of any flagged remote access tools. Remove unauthorized instances and implement appropriate controls."
    },
    "Threat Hunt - Suspicious Processes": {
        "risk": "High",
        "why": "The presence of suspicious processes can indicate malicious activity or unauthorized access.",
        "fix": "Investigate the source and purpose of any flagged suspicious processes. Remove unauthorized instances and implement appropriate controls."
    },
    "Threat Hunt - Network Connections": {
        "risk": "High",
        "why": "Unexpected external network connections may indicate command-and-control activity or unauthorized remote access.",
        "fix": "Review destination IPs, associated processes, firewall rules, and business justification."
    },
    "Threat Hunt - Persistence Indicators": {
    "risk": "High",
    "why": "Persistence mechanisms can allow unauthorized tools or malware to survive reboot and user logon.",
    "fix": "Review flagged scheduled tasks, autoruns, services, and startup entries. Remove unauthorized persistence mechanisms."
},
}

def get_mitre_mapping(check_name):
    return MITRE_MAPPINGS.get(check_name, [])


def get_remediation(check_name, status):
    default = {
        "risk": "Informational",
        "why": "This check helps provide security visibility for the workstation.",
        "fix": "Review the finding and validate it against your local security policy."
    }

    guidance = dict(REMEDIATION_GUIDANCE.get(check_name, default))

    if status == "PASS":
        guidance["action"] = "No action required."
    elif status == "FAIL":
        guidance["action"] = "Prioritize remediation."
    else:
        guidance["action"] = "Review and validate."

    return guidance


def parse_arguments():
    parser = argparse.ArgumentParser(description="Windows Security Audit Tool")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--csv", action="store_true", help="Generate CSV report")
    parser.add_argument("--json", action="store_true", help="Generate JSON report")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")
    parser.add_argument("--summary", action="store_true", help="Print a concise console summary after the scan")
    parser.add_argument("--hunt", action="store_true", help="Enable threat hunting checks")
    parser.add_argument("--output", default="audit_output", help="Output directory")
    parser.add_argument("--pdf", action="store_true", help="Generate PDF report")
    parser.add_argument("--fleet", help="Text file containing computer names, one per line")
    parser.add_argument("--fleet-timeout", type=int, default=30, help="Seconds to wait for each computer during fleet scan")
    parser.add_argument("--baseline", action="store_true", help="Save current audit as baseline")
    parser.add_argument("--compare", help="Compare current audit against a baseline JSON file")
    return parser.parse_args()


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_powershell(command, timeout=30):
    try:
        result = subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0:
            return {
                "ok": False,
                "stdout": stdout,
                "stderr": stderr,
                "error": stderr or f"Command failed with code {result.returncode}",
            }

        return {
            "ok": True,
            "stdout": stdout if stdout else "No output returned",
            "stderr": stderr,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "", "error": "Command timed out"}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": "", "error": str(e)}


def parse_json_output(result):
    if not result.get("ok"):
        return None

    try:
        return json.loads(result["stdout"])
    except Exception:
        return None


def check_result(status, message, score):
    return {"status": status, "message": message, "score": score}


def get_system_info():
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "running_as_admin": is_admin(),
    }


def audit_firewall():
    result = run_powershell(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    )
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Firewall status could not be verified", 5), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    disabled = [p["Name"] for p in data if not p.get("Enabled")]

    if not disabled:
        return check_result("PASS", "All firewall profiles are enabled", 10), result["stdout"]

    return check_result("FAIL", f"Disabled firewall profiles: {', '.join(disabled)}", 0), result["stdout"]


def audit_defender():
    result = run_powershell(
        "Get-MpComputerStatus | "
        "Select-Object AMServiceEnabled, AntivirusEnabled, "
        "RealTimeProtectionEnabled, IoavProtectionEnabled, "
        "AntispywareEnabled, AntivirusSignatureLastUpdated | ConvertTo-Json"
    )
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Microsoft Defender status could not be verified", 5), result["stdout"]

    failures = []
    for key in [
        "AMServiceEnabled",
        "AntivirusEnabled",
        "RealTimeProtectionEnabled",
        "IoavProtectionEnabled",
        "AntispywareEnabled",
    ]:
        if data.get(key) is not True:
            failures.append(key)

    if not failures:
        return check_result("PASS", "Microsoft Defender protections are enabled", 10), result["stdout"]

    return check_result("FAIL", f"Defender issues detected: {', '.join(failures)}", 0), result["stdout"]


def audit_defender_signatures():
    result = run_powershell(
        "Get-MpComputerStatus | "
        "Select-Object AntivirusSignatureLastUpdated,AMEngineVersion,AMProductVersion,QuickScanAge,FullScanAge | "
        "ConvertTo-Json"
    )
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Defender signature status could not be verified", 5), result["stdout"]

    try:
        sig_raw = str(data["AntivirusSignatureLastUpdated"])
        sig_date = datetime.fromisoformat(sig_raw.replace("Z", "").split(".")[0])
        age_days = (datetime.now() - sig_date).days
        full_scan_age = data.get("FullScanAge", "Unknown")

        if age_days <= 3:
            return check_result(
                "PASS",
                f"Signatures are {age_days} day(s) old. Full scan age: {full_scan_age} day(s).",
                10,
            ), result["stdout"]

        if age_days <= 7:
            return check_result("REVIEW", f"Signatures are {age_days} day(s) old. Consider updating.", 6), result["stdout"]

        return check_result("FAIL", f"Signatures are {age_days} day(s) old.", 0), result["stdout"]

    except Exception as e:
        return check_result("REVIEW", f"Could not calculate signature age: {e}", 5), result["stdout"]


def audit_bitlocker():
    result = run_powershell("manage-bde -status C:")
    output = result["stdout"]

    if "Protection Status:    Protection On" in output:
        return check_result("PASS", "BitLocker protection is enabled on C:", 10), output

    if "Protection Status:    Protection Off" in output:
        return check_result("FAIL", "BitLocker protection is off on C:", 0), output

    return check_result("REVIEW", "BitLocker status is unclear", 5), output


def audit_bitlocker_all_volumes():
    command = (
        "Get-BitLockerVolume | "
        "Select-Object MountPoint, VolumeStatus, ProtectionStatus, "
        "EncryptionPercentage, EncryptionMethod, LockStatus | "
        "ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "BitLocker volume coverage could not be verified", 5), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    issues = []
    for volume in data:
        mount = volume.get("MountPoint", "Unknown")
        protection = str(volume.get("ProtectionStatus", "Unknown"))
        encrypted = volume.get("EncryptionPercentage", 0)

        if protection.lower() != "on":
            issues.append(f"{mount} protection is {protection}")

        if encrypted != 100:
            issues.append(f"{mount} encryption is {encrypted}%")

    if not issues:
        return check_result("PASS", f"{len(data)} volume(s) reviewed; all are fully protected", 10), result["stdout"]

    return check_result("REVIEW", "; ".join(issues[:10]), 5), result["stdout"]


def audit_windows_update():
    command = (
        "$session = New-Object -ComObject Microsoft.Update.Session; "
        "$searcher = $session.CreateUpdateSearcher(); "
        "$historyCount = $searcher.GetTotalHistoryCount(); "
        "$history = $searcher.QueryHistory(0, [Math]::Min(10, $historyCount)) | "
        "Select-Object Date, Title, ResultCode; "
        "$pending = $searcher.Search(\"IsInstalled=0 and Type='Software'\").Updates.Count; "
        "[PSCustomObject]@{ PendingUpdates = $pending; RecentHistory = $history } | "
        "ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Windows Update status could not be verified", 5), result["stdout"]

    pending = data.get("PendingUpdates")
    if pending is None:
        return check_result("REVIEW", "Pending update count could not be determined", 5), result["stdout"]

    if pending == 0:
        return check_result("PASS", "No pending Windows software updates found", 10), result["stdout"]

    if pending <= 5:
        return check_result("REVIEW", f"{pending} pending Windows update(s) found", 6), result["stdout"]

    return check_result("FAIL", f"{pending} pending Windows update(s) found", 2), result["stdout"]


def audit_windows_update_age():
    command = (
        "$hotfix = Get-HotFix | "
        "Where-Object { $_.InstalledOn } | "
        "Sort-Object InstalledOn -Descending | "
        "Select-Object -First 1 HotFixID, Description, InstalledOn; "
        "$ageDays = if ($hotfix.InstalledOn) { "
        "(New-TimeSpan -Start $hotfix.InstalledOn -End (Get-Date)).Days "
        "} else { $null }; "
        "[PSCustomObject]@{ "
        "HotFixID = $hotfix.HotFixID; "
        "Description = $hotfix.Description; "
        "InstalledOn = $hotfix.InstalledOn.ToString('yyyy-MM-dd'); "
        "AgeDays = $ageDays "
        "} | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Last installed Windows update could not be verified", 5), result["stdout"]

    age_days = data.get("AgeDays")
    hotfix_id = data.get("HotFixID", "Unknown")
    installed_on = data.get("InstalledOn", "Unknown")

    if age_days is None:
        return check_result("REVIEW", "Windows Update age could not be calculated", 5), result["stdout"]

    if age_days <= 30:
        return check_result("PASS", f"Last installed update {hotfix_id} was installed on {installed_on} ({age_days} day(s) ago)", 10), result["stdout"]

    if age_days <= 60:
        return check_result("REVIEW", f"Last installed update {hotfix_id} was installed on {installed_on} ({age_days} day(s) ago)", 6), result["stdout"]

    return check_result("FAIL", f"Last installed update {hotfix_id} was installed on {installed_on} ({age_days} day(s) ago)", 0), result["stdout"]


def audit_rdp():
    command = (
        "$rdp = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections; "
        "$nla = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication; "
        "$fw = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | "
        "Select-Object DisplayName, Enabled, Direction, Action; "
        "[PSCustomObject]@{ "
        "RdpEnabled = ($rdp.fDenyTSConnections -eq 0); "
        "NlaEnabled = ($nla.UserAuthentication -eq 1); "
        "FirewallRules = $fw "
        "} | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "RDP status could not be verified", 5), result["stdout"]

    rdp_enabled = data.get("RdpEnabled")
    nla_enabled = data.get("NlaEnabled")

    if rdp_enabled is False:
        return check_result("PASS", "RDP is disabled", 10), result["stdout"]

    if rdp_enabled is True and nla_enabled is True:
        return check_result("REVIEW", "RDP is enabled, but Network Level Authentication is enabled", 6), result["stdout"]

    if rdp_enabled is True and nla_enabled is False:
        return check_result("FAIL", "RDP is enabled and Network Level Authentication is disabled", 0), result["stdout"]

    return check_result("REVIEW", "RDP status is unclear", 5), result["stdout"]


def audit_smb():
    command = (
        "$smb = Get-SmbServerConfiguration | "
        "Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, "
        "EnableSecuritySignature, EnableInsecureGuestLogons; "
        "$smb | ConvertTo-Json"
    )
    result = run_powershell(command)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "SMB configuration could not be verified", 5), result["stdout"]

    issues = []
    if data.get("EnableSMB1Protocol") is True:
        issues.append("SMBv1 is enabled")

    if data.get("EnableInsecureGuestLogons") is True:
        issues.append("Insecure guest logons are enabled")

    if data.get("RequireSecuritySignature") is not True:
        issues.append("SMB signing is not required")

    if not issues:
        return check_result("PASS", "SMBv1 disabled, guest logons disabled, and SMB signing required", 10), result["stdout"]

    if "SMBv1 is enabled" in issues or "Insecure guest logons are enabled" in issues:
        return check_result("FAIL", "; ".join(issues), 2), result["stdout"]

    return check_result("REVIEW", "; ".join(issues), 6), result["stdout"]


def audit_uac():
    command = (
        "$uac = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; "
        "[PSCustomObject]@{ "
        "EnableLUA = $uac.EnableLUA; "
        "ConsentPromptBehaviorAdmin = $uac.ConsentPromptBehaviorAdmin; "
        "PromptOnSecureDesktop = $uac.PromptOnSecureDesktop; "
        "FilterAdministratorToken = $uac.FilterAdministratorToken "
        "} | ConvertTo-Json"
    )
    result = run_powershell(command)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "UAC status could not be verified", 5), result["stdout"]

    issues = []
    if data.get("EnableLUA") != 1:
        issues.append("UAC is disabled")

    if data.get("ConsentPromptBehaviorAdmin") == 0:
        issues.append("Admin elevation prompts are disabled")

    if data.get("PromptOnSecureDesktop") != 1:
        issues.append("Secure desktop prompt is disabled")

    if not issues:
        return check_result("PASS", "UAC is enabled with secure elevation prompts", 10), result["stdout"]

    if "UAC is disabled" in issues:
        return check_result("FAIL", "; ".join(issues), 0), result["stdout"]

    return check_result("REVIEW", "; ".join(issues), 6), result["stdout"]


def audit_secure_boot_tpm():
    command = (
        "$secureBoot = $false; "
        "try { $secureBoot = Confirm-SecureBootUEFI } catch {} "
        "$tpm = Get-Tpm; "
        "[PSCustomObject]@{ "
        "SecureBootEnabled = $secureBoot; "
        "TpmPresent = $tpm.TpmPresent; "
        "TpmReady = $tpm.TpmReady; "
        "TpmEnabled = $tpm.TpmEnabled "
        "} | ConvertTo-Json"
    )
    result = run_powershell(command)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Secure Boot / TPM status could not be verified", 5), result["stdout"]

    issues = []
    if not data.get("SecureBootEnabled"):
        issues.append("Secure Boot disabled")

    if not data.get("TpmPresent"):
        issues.append("TPM not present")

    if data.get("TpmPresent") and not data.get("TpmReady"):
        issues.append("TPM not ready")

    if not issues:
        return check_result("PASS", "Secure Boot enabled and TPM ready", 10), result["stdout"]

    if "TPM not present" in issues:
        return check_result("FAIL", "; ".join(issues), 0), result["stdout"]

    return check_result("REVIEW", "; ".join(issues), 5), result["stdout"]


def audit_event_logging():
    result = run_powershell("auditpol /get /category:*")
    output = result["stdout"]

    if not output:
        return check_result("REVIEW", "Audit policy could not be verified", 5), output

    important_categories = ["Logon", "Account Logon", "Account Management", "Policy Change", "Privilege Use"]
    missing = [category for category in important_categories if category not in output]

    if not missing:
        return check_result("PASS", "Critical audit categories detected", 10), output

    return check_result("REVIEW", f"Could not verify: {', '.join(missing)}", 6), output


def audit_installed_software():
    command = (
        "$paths = @("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        "); "
        "$apps = Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | "
        "Sort-Object DisplayName; "
        "$apps | ConvertTo-Json -Depth 3"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Installed software inventory could not be verified", 5), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    risky_keywords = [
        "teamviewer", "anydesk", "vnc", "ultravnc", "tightvnc", "logmein",
        "screenconnect", "connectwise", "splashtop", "java", "utorrent",
        "bittorrent", "wireshark", "nmap"
    ]

    flagged = []
    for app in data:
        name = str(app.get("DisplayName", "")).lower()
        if any(keyword in name for keyword in risky_keywords):
            flagged.append(app.get("DisplayName"))

    if not flagged:
        return check_result("PASS", f"{len(data)} installed application(s) reviewed; no risky software keywords found", 10), result["stdout"]

    return check_result("REVIEW", f"{len(flagged)} potentially risky application(s) found: {', '.join(flagged[:10])}", 5), result["stdout"]


def audit_scheduled_tasks():
    command = (
        "$tasks = Get-ScheduledTask | "
        "Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | "
        "Select-Object TaskName, TaskPath, State, Author, "
        "@{Name='Execute';Expression={$_.Actions.Execute}}, "
        "@{Name='Arguments';Expression={$_.Actions.Arguments}}; "
        "$tasks | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Scheduled tasks could not be verified", 5), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    suspicious_keywords = [
        "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
        "regsvr32", "bitsadmin", "certutil", "appdata", "temp", "public", "downloads"
    ]

    flagged = []
    for task in data:
        combined = " ".join([
            str(task.get("TaskName", "")),
            str(task.get("TaskPath", "")),
            str(task.get("Author", "")),
            str(task.get("Execute", "")),
            str(task.get("Arguments", "")),
        ]).lower()

        if any(keyword in combined for keyword in suspicious_keywords):
            flagged.append(f"{task.get('TaskPath', '')}{task.get('TaskName', '')}")

    if not flagged:
        return check_result("PASS", f"{len(data)} non-Microsoft scheduled task(s) reviewed; no suspicious keywords found", 10), result["stdout"]

    return check_result("REVIEW", f"{len(flagged)} suspicious scheduled task(s) found: {', '.join(flagged[:10])}", 5), result["stdout"]


def audit_autoruns_registry():
    command = (
        "$paths = @("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce'"
        "); "
        "$items = foreach ($path in $paths) { "
        "if (Test-Path $path) { "
        "$props = Get-ItemProperty -Path $path; "
        "$props.PSObject.Properties | "
        "Where-Object { $_.Name -notlike 'PS*' } | "
        "Select-Object @{Name='RegistryPath';Expression={$path}}, Name, Value "
        "} "
        "}; "
        "$items | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("PASS", "No autorun registry entries found", 10), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    suspicious_keywords = [
        "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
        "regsvr32", "bitsadmin", "certutil", "appdata", "temp", "public",
        "downloads", "startup", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".scr"
    ]

    flagged = []
    for item in data:
        combined = " ".join([
            str(item.get("RegistryPath", "")),
            str(item.get("Name", "")),
            str(item.get("Value", "")),
        ]).lower()

        if any(keyword in combined for keyword in suspicious_keywords):
            flagged.append(f"{item.get('RegistryPath')}\\{item.get('Name')}")

    if not flagged:
        return check_result("PASS", f"{len(data)} autorun registry entry/entries reviewed; no suspicious keywords found", 10), result["stdout"]

    return check_result("REVIEW", f"{len(flagged)} suspicious autorun entry/entries found: {', '.join(flagged[:10])}", 5), result["stdout"]


def audit_startup_folders():
    command = (
        "$paths = @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup')); "
        "$items = foreach ($path in $paths) { "
        "if (Test-Path $path) { "
        "Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue | "
        "Select-Object @{Name='StartupPath';Expression={$path}}, Name, FullName, Extension, Length, LastWriteTime "
        "} "
        "}; "
        "$items | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("PASS", "No startup folder items found", 10), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    suspicious_extensions = [".ps1", ".vbs", ".js", ".jse", ".wsf", ".bat", ".cmd", ".scr", ".hta", ".lnk", ".exe"]

    flagged = []
    for item in data:
        extension = str(item.get("Extension", "")).lower()
        full_name = str(item.get("FullName", "")).lower()

        if extension in suspicious_extensions or "appdata" in full_name or "temp" in full_name:
            flagged.append(item.get("FullName"))

    if not flagged:
        return check_result("PASS", f"{len(data)} startup folder item(s) reviewed; no suspicious items found", 10), result["stdout"]

    return check_result("REVIEW", f"{len(flagged)} suspicious startup folder item(s) found: {', '.join(flagged[:10])}", 5), result["stdout"]


def audit_windows_services():
    command = (
        "$services = Get-CimInstance Win32_Service | "
        "Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' } | "
        "Select-Object Name, DisplayName, State, StartMode, StartName, PathName; "
        "$services | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Windows services could not be verified", 5), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    suspicious_keywords = [
        "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
        "regsvr32", "bitsadmin", "certutil", "appdata", "temp", "public",
        "downloads", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".scr"
    ]

    flagged = []
    for service in data:
        combined = " ".join([
            str(service.get("Name", "")),
            str(service.get("DisplayName", "")),
            str(service.get("PathName", "")),
        ]).lower()

        keyword_hit = any(keyword in combined for keyword in suspicious_keywords)
        path = str(service.get("PathName", ""))
        unquoted_path = path and " " in path and not path.strip().startswith('"') and ".exe" in path.lower()

        if keyword_hit or unquoted_path:
            flagged.append(service.get("DisplayName") or service.get("Name"))

    if not flagged:
        return check_result("PASS", f"{len(data)} running automatic service(s) reviewed; no suspicious service indicators found", 10), result["stdout"]

    return check_result("REVIEW", f"{len(flagged)} suspicious service indicator(s) found: {', '.join(flagged[:10])}", 5), result["stdout"]


def audit_local_admins():
    result = run_powershell(
        "Get-LocalGroupMember -Group Administrators | "
        "Select-Object Name, ObjectClass, PrincipalSource | ConvertTo-Json"
    )
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Local administrators could not be verified", 5), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    admin_count = len(data)

    if admin_count <= 2:
        return check_result("PASS", f"{admin_count} local administrator account(s) found", 10), result["stdout"]

    return check_result("REVIEW", f"{admin_count} local administrator account(s) found", 5), result["stdout"]


def audit_local_users():
    command = (
        "$users = Get-LocalUser | "
        "Select-Object Name, Enabled, LastLogon, PasswordRequired, "
        "PasswordLastSet, UserMayChangePassword, PasswordExpires, AccountExpires, Description; "
        "$users | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Local user accounts could not be verified", 5), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    issues = []
    for user in data:
        name = str(user.get("Name", ""))
        enabled = user.get("Enabled")
        password_required = user.get("PasswordRequired")

        if name.lower() == "guest" and enabled:
            issues.append("Guest account is enabled")

        if enabled and password_required is False:
            issues.append(f"{name} does not require a password")

        if enabled and name.lower() in ["administrator", "admin", "test", "temp"]:
            issues.append(f"Review enabled local account: {name}")

    if not issues:
        return check_result("PASS", f"{len(data)} local user account(s) reviewed; no obvious issues found", 10), result["stdout"]

    if "Guest account is enabled" in issues:
        return check_result("FAIL", "; ".join(issues[:10]), 2), result["stdout"]

    return check_result("REVIEW", "; ".join(issues[:10]), 6), result["stdout"]


def audit_password_policy():
    result = run_powershell("net accounts")
    output = result["stdout"]

    score = 10
    issues = []

    if "Minimum password length:" in output:
        try:
            line = [x for x in output.splitlines() if "Minimum password length:" in x][0]
            length = int(line.split(":")[-1].strip())
            if length < 12:
                score -= 4
                issues.append(f"Minimum password length is {length}")
        except Exception:
            issues.append("Could not parse minimum password length")
            score -= 2

    if "Lockout threshold:" in output:
        try:
            line = [x for x in output.splitlines() if "Lockout threshold:" in x][0]
            value = line.split(":")[-1].strip()
            if value.lower() == "never":
                score -= 4
                issues.append("Account lockout threshold is never")
        except Exception:
            issues.append("Could not parse lockout threshold")
            score -= 2
    else:
        score -= 3
        issues.append("Lockout threshold not found")

    if issues:
        return check_result("REVIEW", "; ".join(issues), max(score, 0)), output

    return check_result("PASS", "Password and lockout policy detected", 10), output


def audit_failed_logins():
    result = run_powershell('wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:10 /f:text')
    output = result["stdout"]

    if "No events were found" in output:
        return check_result("PASS", "No recent failed login events found", 10), output

    if "Event ID: 4625" in output:
        count = output.count("Event ID: 4625")
        return check_result("REVIEW", f"{count} recent failed login event(s) found", 5), output

    return check_result("REVIEW", "Failed login status could not be verified", 5), output


def audit_network_shares():
    command = (
        "$shares = Get-SmbShare | "
        "Where-Object { $_.Name -notin @('ADMIN$', 'C$', 'IPC$', 'print$') } | "
        "Select-Object Name, Path, Description, ShareState, FolderEnumerationMode, "
        "CachingMode, ContinuouslyAvailable, EncryptData; "
        "$shares | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("PASS", "No non-default SMB network shares found", 10), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    issues = []
    for share in data:
        name = str(share.get("Name", ""))
        path = str(share.get("Path", ""))
        encrypt_data = share.get("EncryptData")

        if encrypt_data is not True:
            issues.append(f"{name} does not require SMB encryption")

        if path.lower().startswith("c:\\users"):
            issues.append(f"{name} points to a user profile path")

        if path.lower().startswith("c:\\"):
            issues.append(f"Review local drive share: {name} -> {path}")

    if not issues:
        return check_result("PASS", f"{len(data)} non-default network share(s) reviewed; no obvious issues found", 10), result["stdout"]

    return check_result("REVIEW", f"{len(data)} non-default share(s) found: " + "; ".join(issues[:10]), 5), result["stdout"]


def audit_share_permissions():
    command = (
        "$shares = Get-SmbShare | "
        "Where-Object { $_.Name -notin @('ADMIN$', 'C$', 'IPC$', 'print$') }; "
        "$results = foreach ($share in $shares) { "
        "Get-SmbShareAccess -Name $share.Name | "
        "Select-Object @{Name='Share';Expression={$share.Name}}, AccountName, AccessControlType, AccessRight "
        "}; "
        "$results | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("PASS", "No custom share permissions found", 10), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    critical_accounts = ["Everyone", "Guest", "Guests", "ANONYMOUS LOGON"]
    review_accounts = ["Authenticated Users"]

    warnings = []
    critical = []

    for permission in data:
        account = str(permission.get("AccountName", ""))
        share = str(permission.get("Share", ""))
        access = str(permission.get("AccessRight", ""))

        if account in critical_accounts:
            if access.lower() in ["full", "change"]:
                critical.append(f"{share}: {account} has {access} access")
            else:
                warnings.append(f"{share}: {account} has {access} access")

        if account in review_accounts:
            if access.lower() == "full":
                critical.append(f"{share}: {account} has Full access")
            else:
                warnings.append(f"{share}: {account} has {access} access")

    if critical:
        return check_result("FAIL", "; ".join(critical[:10]), 0), result["stdout"]

    if warnings:
        return check_result("REVIEW", "; ".join(warnings[:10]), 5), result["stdout"]

    return check_result("PASS", "No risky share permissions detected", 10), result["stdout"]


def audit_lsa_credential_guard():
    command = (
        "$lsa = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue; "
        "$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue; "
        "[PSCustomObject]@{ "
        "RunAsPPL = $lsa.RunAsPPL; "
        "RunAsPPLBoot = $lsa.RunAsPPLBoot; "
        "SecurityServicesConfigured = $dg.SecurityServicesConfigured; "
        "SecurityServicesRunning = $dg.SecurityServicesRunning; "
        "VirtualizationBasedSecurityStatus = $dg.VirtualizationBasedSecurityStatus "
        "} | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "LSA/Credential Guard status could not be verified", 5), result["stdout"]

    issues = []
    if data.get("RunAsPPL") != 1:
        issues.append("LSA Protection is not enabled")

    running = data.get("SecurityServicesRunning") or []
    if isinstance(running, int):
        running = [running]

    if 1 not in running:
        issues.append("Credential Guard does not appear to be running")

    if not issues:
        return check_result("PASS", "LSA Protection and Credential Guard appear enabled", 10), result["stdout"]

    return check_result("REVIEW", "; ".join(issues), 5), result["stdout"]


def audit_defender_asr_rules():
    command = (
        "$prefs = Get-MpPreference; "
        "[PSCustomObject]@{ "
        "AttackSurfaceReductionRules_Ids = $prefs.AttackSurfaceReductionRules_Ids; "
        "AttackSurfaceReductionRules_Actions = $prefs.AttackSurfaceReductionRules_Actions "
        "} | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Defender ASR rule status could not be verified", 5), result["stdout"]

    ids = data.get("AttackSurfaceReductionRules_Ids") or []
    actions = data.get("AttackSurfaceReductionRules_Actions") or []

    if isinstance(ids, str):
        ids = [ids]

    if isinstance(actions, int):
        actions = [actions]

    enabled_count = sum(1 for action in actions if action == 1)
    audit_count = sum(1 for action in actions if action == 2)
    disabled_count = sum(1 for action in actions if action == 0)

    if not ids:
        return check_result("FAIL", "No Defender ASR rules configured", 0), result["stdout"]

    if enabled_count >= 5:
        return check_result("PASS", f"{enabled_count} ASR rule(s) enabled, {audit_count} in audit mode, {disabled_count} disabled", 10), result["stdout"]

    if enabled_count > 0 or audit_count > 0:
        return check_result("REVIEW", f"{enabled_count} ASR rule(s) enabled, {audit_count} in audit mode, {disabled_count} disabled", 6), result["stdout"]

    return check_result("FAIL", "ASR rules exist but none are enabled or in audit mode", 0), result["stdout"]


def audit_listening_connections():
    command = (
        "$connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress, LocalPort, State, OwningProcess, "
        "@{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, "
        "@{Name='ProcessPath';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}; "
        "$connections | Sort-Object LocalPort | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Listening connections could not be verified", 5), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    risky_ports = {
        21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 135: "RPC",
        139: "NetBIOS", 445: "SMB", 1433: "SQL Server", 3306: "MySQL",
        3389: "RDP", 5900: "VNC", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
        8080: "HTTP alternate",
    }

    findings = []
    for conn in data:
        port = conn.get("LocalPort")
        address = str(conn.get("LocalAddress", ""))
        process = str(conn.get("ProcessName", "Unknown"))

        try:
            port = int(port)
        except Exception:
            continue

        if port in risky_ports:
            findings.append(f"{risky_ports[port]} port {port} listening on {address} by {process}")

    if not findings:
        return check_result("PASS", f"{len(data)} listening TCP port(s) reviewed; no common risky ports found", 10), result["stdout"]

    return check_result("REVIEW", f"{len(findings)} notable listening port(s): " + "; ".join(findings[:10]), 5), result["stdout"]


def audit_powershell_security():
    command = (
        "$paths = @{ "
        "ScriptBlockLogging = 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging'; "
        "ModuleLogging = 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging'; "
        "Transcription = 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' "
        "}; "
        "$v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue; "
        "$result = [PSCustomObject]@{ "
        "ScriptBlockLogging = (Get-ItemProperty -Path $paths.ScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging; "
        "ModuleLogging = (Get-ItemProperty -Path $paths.ModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging; "
        "Transcription = (Get-ItemProperty -Path $paths.Transcription -ErrorAction SilentlyContinue).EnableTranscripting; "
        "PowerShellV2State = $v2.State "
        "}; "
        "$result | ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "PowerShell security settings could not be verified", 5), result["stdout"]

    issues = []
    if data.get("ScriptBlockLogging") != 1:
        issues.append("Script Block Logging is not enabled")

    if data.get("ModuleLogging") != 1:
        issues.append("Module Logging is not enabled")

    if data.get("Transcription") != 1:
        issues.append("PowerShell Transcription is not enabled")

    if str(data.get("PowerShellV2State", "")).lower() == "enabled":
        issues.append("PowerShell v2 is enabled")

    if not issues:
        return check_result("PASS", "PowerShell logging is enabled and PowerShell v2 is disabled", 10), result["stdout"]

    return check_result("REVIEW", "; ".join(issues), 5), result["stdout"]


def audit_usb_storage():
    command = (
        "$usbStor = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -ErrorAction SilentlyContinue; "
        "$policyPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices'; "
        "$policyExists = Test-Path $policyPath; "
        "[PSCustomObject]@{ USBSTORStart = $usbStor.Start; RemovableStoragePolicyExists = $policyExists } | "
        "ConvertTo-Json -Depth 4"
    )
    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "USB storage status could not be verified", 5), result["stdout"]

    issues = []
    usb_start = data.get("USBSTORStart")

    if usb_start == 4:
        return check_result("PASS", "USB mass storage is disabled", 10), result["stdout"]

    if usb_start == 3:
        issues.append("USB mass storage is enabled")

    if not data.get("RemovableStoragePolicyExists"):
        issues.append("No removable storage restriction policy detected")

    if issues:
        return check_result("REVIEW", "; ".join(issues), 5), result["stdout"]

    return check_result("PASS", "USB storage settings reviewed; no obvious issues found", 10), result["stdout"]

def parse_version_parts(version):
    parts = []

    for piece in str(version).replace(",", ".").replace("-", ".").split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())

        if digits:
            parts.append(int(digits))

    return parts


def version_less_than(version, minimum):
    current = parse_version_parts(version)
    required = parse_version_parts(minimum)

    if not current:
        return False

    length = max(len(current), len(required))
    current += [0] * (length - len(current))
    required += [0] * (length - len(required))

    return current < required


def audit_vulnerable_software():
    command = (
        "$paths = @("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        "); "
        "$apps = Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | "
        "Sort-Object DisplayName; "
        "$apps | ConvertTo-Json -Depth 4"
    )

    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result(
            "REVIEW",
            "Installed software could not be reviewed for vulnerable or end-of-life applications",
            5
        ), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    findings = []

    eol_patterns = [
        ("java 8", "Java 8 detected; review for end-of-life or required business exception"),
        ("java(tm) 8", "Java 8 detected; review for end-of-life or required business exception"),
        ("jre 8", "Java Runtime Environment 8 detected"),
        ("jdk 8", "Java Development Kit 8 detected"),
        ("office 2010", "Microsoft Office 2010 is end-of-life"),
        ("office 2013", "Microsoft Office 2013 is end-of-life"),
        ("office 2016", "Microsoft Office 2016 should be reviewed for lifecycle/support status"),
        ("internet explorer", "Internet Explorer component/application detected"),
        ("silverlight", "Microsoft Silverlight is end-of-life"),
        ("flash player", "Adobe Flash Player is end-of-life"),
        ("quicktime", "Apple QuickTime for Windows is unsupported"),
        ("shockwave", "Adobe Shockwave is end-of-life"),
        ("python 2.", "Python 2 is end-of-life"),
        ("wireshark 2.", "Old Wireshark major version detected"),
        ("wireshark 3.", "Older Wireshark major version detected; verify patch level"),
    ]

    for app in data:
        name = str(app.get("DisplayName", "")).strip()
        version = str(app.get("DisplayVersion", "") or "").strip()
        publisher = str(app.get("Publisher", "") or "").strip()
        combined = f"{name} {version} {publisher}".lower()

        for pattern, message in eol_patterns:
            if pattern in combined:
                findings.append(f"{name} {version}: {message}")
                break

        lowered_name = name.lower()

        if "7-zip" in lowered_name and version_less_than(version, "23.01"):
            findings.append(f"{name} {version}: 7-Zip version is older than 23.01; update recommended")

        if "mozilla firefox" in lowered_name and version_less_than(version, "115"):
            findings.append(f"{name} {version}: Firefox appears older than ESR 115; update recommended")

        if "google chrome" in lowered_name and version_less_than(version, "120"):
            findings.append(f"{name} {version}: Chrome appears older than version 120; update recommended")

        if "microsoft edge" in lowered_name and version_less_than(version, "120"):
            findings.append(f"{name} {version}: Edge appears older than version 120; update recommended")

        if ("adobe acrobat reader" in lowered_name or "adobe reader" in lowered_name) and version_less_than(version, "23"):
            findings.append(f"{name} {version}: Adobe Reader/Acrobat appears older than 2023 release family; update recommended")

    findings = sorted(set(findings))

    if not findings:
        return check_result(
            "PASS",
            f"{len(data)} installed application(s) reviewed; no common vulnerable or end-of-life software indicators found",
            10
        ), result["stdout"]

    high_confidence = [
        finding for finding in findings
        if any(term in finding.lower() for term in [
            "end-of-life",
            "unsupported",
            "flash",
            "silverlight",
            "quicktime",
            "python 2",
            "office 2010",
            "office 2013",
        ])
    ]

    if high_confidence:
        return check_result(
            "FAIL",
            f"{len(findings)} vulnerable/end-of-life software indicator(s) found: {', '.join(findings[:10])}",
            0
        ), result["stdout"]

    return check_result(
        "REVIEW",
        f"{len(findings)} software version indicator(s) should be reviewed: {', '.join(findings[:10])}",
        5
    ), result["stdout"]


def get_letter_grade(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def get_score_band(score):
    if score >= 85:
        return "good"
    if score >= 70:
        return "fair"
    return "poor"


def get_check_category(check_name):
    categories = {
        "Threat Hunting": [
            "Threat Hunt - Remote Access Tools",
            "Threat Hunt - Suspicious Processes",
            "Threat Hunt - Persistence Indicators",
            "Threat Hunt - Network Connections",
        ],
        "Vulnerability Intelligence": [
            "Vulnerable Software Detection",
        ],
        "Endpoint Protection": [
            "Microsoft Defender",
            "Defender Signatures",
            "Defender ASR Rules",
            "PowerShell Security",
        ],
        "Patch Management": [
            "Windows Update",
            "Windows Update Age",
        ],
        "Network Exposure": [
            "Firewall",
            "RDP",
            "SMB",
            "Listening Connections",
            "Network Shares",
            "Share Permissions",
        ],
        "Identity & Access": [
            "Local Administrators",
            "Local Users",
            "Password Policy",
            "Failed Logins",
            "UAC",
            "LSA / Credential Guard",
        ],
        "Data Protection": [
            "BitLocker",
            "BitLocker All Volumes",
            "Secure Boot / TPM",
            "USB Storage",
        ],
        "Logging & Visibility": [
            "Event Logging",
        ],
        "Persistence Review": [
            "Installed Software",
            "Scheduled Tasks",
            "Autorun Registry Keys",
            "Startup Folders",
            "Windows Services",
        ],
    }

    for category, checks in categories.items():
        if check_name in checks:
            return category

    return "Other"


def save_to_json(data, filename):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def save_to_csv(data, filename):
    flat = {
        "hostname": data["system"]["hostname"],
        "scan_time": data["system"]["scan_time"],
        "running_as_admin": data["system"]["running_as_admin"],
        "overall_score": data["overall_score"],
        "overall_grade": data.get("overall_grade", get_letter_grade(data.get("overall_score", 0))),
    }

    for check_name, check_data in data["checks"].items():
        summary = check_data["summary"]
        remediation = summary.get("remediation", {})
        check_data["summary"]["mitre"] = get_mitre_mapping(check_name)

        flat[f"{check_name}_status"] = summary.get("status", "")
        flat[f"{check_name}_message"] = summary.get("message", "")
        flat[f"{check_name}_score"] = summary.get("score", "")
        flat[f"{check_name}_weight"] = summary.get("weight", "")
        flat[f"{check_name}_risk"] = remediation.get("risk", "")
        flat[f"{check_name}_recommended_fix"] = remediation.get("fix", "")

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=flat.keys())
        writer.writeheader()
        writer.writerow(flat)


def save_to_html(data, filename, include_raw=True):
    system = data["system"]
    overall_score = data.get("overall_score", 0)
    overall_grade = data.get("overall_grade", get_letter_grade(overall_score))
    score_band = get_score_band(overall_score)


    grade_class = {
        "A": "grade-a",
        "B": "grade-b",
        "C": "grade-c",
        "D": "grade-d",
        "F": "grade-f",
    }.get(overall_grade, "grade-f")

    grade_text = {
        "A": "Excellent Security Posture",
        "B": "Good Security Posture",
        "C": "Moderate Security Risk",
        "D": "High Security Risk",
        "F": "Critical Security Issues Detected",
    }.get(overall_grade, "Security posture could not be classified")

    status_counts = {"PASS": 0, "REVIEW": 0, "FAIL": 0}
    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    category_map = {}
    priority_rows = ""

    for name, check in data["checks"].items():
        summary = check["summary"]
        status = summary.get("status", "REVIEW")
        remediation = summary.get("remediation", {})
        risk = remediation.get("risk", "Informational")
        category = get_check_category(name)

        status_counts[status] = status_counts.get(status, 0) + 1
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        category_map.setdefault(category, []).append((name, check))

        if status in ["FAIL", "REVIEW"]:
            priority_rows += f"""
            <tr>
                <td>{html.escape(name)}</td>
                <td><span class="badge {html.escape(status.lower())}">{html.escape(status)}</span></td>
                <td>{html.escape(str(risk))}</td>
                <td>{html.escape(str(summary.get('message', '')))}</td>
                <td>{html.escape(str(remediation.get('fix', 'Review and validate.')))}</td>
            </tr>
            """

    if not priority_rows:
        priority_rows = """
        <tr>
            <td colspan="5">No FAIL or REVIEW findings were detected.</td>
        </tr>
        """
    
        category_sections = ""

    category_sections = ""

    for category in sorted(category_map.keys()):
        checks = category_map[category]
        rows = ""

        for name, check in checks:
            summary = check["summary"]
            status = html.escape(str(summary.get("status", "REVIEW")))
            message = html.escape(str(summary.get("message", "")))
            score = html.escape(str(summary.get("score", "")))
            weight = html.escape(str(summary.get("weight", 5)))
            remediation = summary.get("remediation", {})
            risk = html.escape(str(remediation.get("risk", "")))
            mitre_entries = summary.get("mitre", [])
            mitre_text = "<br>".join(
                f"{technique}: {technique_name}"
                for technique, technique_name in mitre_entries
            )
            why = html.escape(str(remediation.get("why", "")))
            fix = html.escape(str(remediation.get("fix", "")))
            action = html.escape(str(remediation.get("action", "")))
            css_class = status.lower()

            

            rows += f"""
            <tr>
                <td class="check-name">{html.escape(name)}</td>
                <td><span class="badge {css_class}">{status}</span></td>
                <td>{message}</td>
                <td>{score}/10</td>
                <td>{weight}</td>
                <td>{risk}</td>
                <td>{mitre_text}</td>
                <td>
                    <strong>{action}</strong><br>
                    <span class="muted">Why:</span> {why}<br>
                    <span class="muted">Fix:</span> {fix}
                </td>
            </tr>
            """

        category_sections += f"""
        <section class="card">
            <h2>{html.escape(category)}</h2>
            <div class="table-wrap">
                <table>
                    <tr>
                        <th>Check</th>
                        <th>Status</th>
                        <th>Finding</th>
                        <th>Score</th>
                        <th>Weight</th>
                        <th>Risk</th>
                        <th>MITRE ATT&CK</th>
                        <th>Remediation</th>
                    </tr>
                    {rows}
                </table>
            </div>
        </section>
        """

    raw_sections = ""

    for name, check in data["checks"].items():
        raw_sections += f"""
        <details>
            <summary>{html.escape(name)}</summary>
            <pre>{html.escape(str(check.get('raw', '')))}</pre>
        </details>
        """

    raw_audit_section = ""

    if include_raw:
        raw_audit_section = f"""
        <section class="card">
            <h2>Raw Audit Data</h2>
            <p>Expand a section to view the raw PowerShell output used by the check.</p>
            {raw_sections}
        </section>
        """

    report = f"""
            <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
        <title>Windows Security Audit Report</title>
        <style>
            :root {{
                --bg: #f5f7fb;
                --card: #ffffff;
                --text: #1f2937;
                --muted: #6b7280;
                --border: #d8dee9;
                --pass: #15803d;
                --review: #b45309;
                --fail: #b91c1c;
                --good-bg: #dcfce7;
                --fair-bg: #fef3c7;
                --poor-bg: #fee2e2;
            }}

            * {{ box-sizing: border-box; }}

            body {{
                margin: 0;
                background: var(--bg);
                color: var(--text);
                font-family: Arial, Helvetica, sans-serif;
                line-height: 1.45;
            }}

            header {{
                background: #111827;
                color: white;
                padding: 28px 40px;
            }}

            header h1 {{ margin: 0 0 8px 0; }}
            header p {{ margin: 0; color: #d1d5db; }}
            main {{ padding: 28px 40px; }}

            .grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 16px;
                margin-bottom: 20px;
            }}

            .card {{
                background: var(--card);
                border: 1px solid var(--border);
                border-radius: 12px;
                padding: 18px;
                margin-bottom: 20px;
                box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
            }}

            .metric {{
                background: var(--card);
                border: 1px solid var(--border);
                border-radius: 12px;
                padding: 18px;
            }}

            .metric .label,
            .score-box .label {{
                color: var(--muted);
                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: 0.04em;
                font-weight: bold;
            }}

            .metric .value {{
                font-size: 30px;
                font-weight: bold;
                margin-top: 6px;
            }}

            .score-box {{
                border-radius: 14px;
                padding: 22px;
                border: 1px solid var(--border);
            }}

            .score-box.good {{ background: var(--good-bg); }}
            .score-box.fair {{ background: var(--fair-bg); }}
            .score-box.poor {{ background: var(--poor-bg); }}

            .score-number {{
                font-size: 56px;
                font-weight: bold;
                line-height: 1;
                margin-top: 10px;
            }}

            .score-subtitle {{
                font-size: 18px;
                color: #4b5563;
                margin-top: 8px;
            }}

            .grade-description {{
                margin-top: 8px;
                font-size: 16px;
                font-weight: bold;
            }}

            
            .grade-a {{ color: #15803d; }}
            .grade-b {{ color: #16a34a; }}
            .grade-c {{ color: #ca8a04; }}
            .grade-d {{ color: #b45309; }}
            .grade-f {{ color: #b91c1c; }}

                

            .table-wrap {{ overflow-x: auto; }}

            table {{
                border-collapse: collapse;
                width: 100%;
                min-width: 950px;
            }}

            th, td {{
                border-bottom: 1px solid var(--border);
                padding: 10px;
                text-align: left;
                vertical-align: top;
            }}

            th {{
                background: #f3f4f6;
                font-size: 13px;
                text-transform: uppercase;
                color: #374151;
            }}

            .badge {{
                display: inline-block;
                min-width: 72px;
                text-align: center;
                border-radius: 999px;
                padding: 4px 9px;
                color: white;
                font-weight: bold;
                font-size: 12px;
            }}

            .badge.pass {{ background: var(--pass); }}
            .badge.review {{ background: var(--review); }}
            .badge.fail {{ background: var(--fail); }}

            .check-name {{ font-weight: bold; }}
            .muted {{ color: var(--muted); font-weight: bold; }}

            dl {{
                display: grid;
                grid-template-columns: 180px 1fr;
                gap: 8px 16px;
                margin: 0;
            }}

            dt {{ font-weight: bold; color: var(--muted); }}
            dd {{ margin: 0; }}

            details {{
                background: white;
                border: 1px solid var(--border);
                border-radius: 10px;
                margin-bottom: 10px;
                padding: 12px;
            }}

            summary {{
                cursor: pointer;
                font-weight: bold;
            }}

            pre {{
                white-space: pre-wrap;
                overflow-x: auto;
                background: #0f172a;
                color: #e5e7eb;
                padding: 14px;
                border-radius: 8px;
            }}

            footer {{
                color: var(--muted);
                font-size: 12px;
                padding: 0 40px 28px 40px;
            }}
        </style>
    </head>
    <body>
        <header>
            <h1>Windows Security Audit Report</h1>
            <p>{html.escape(str(system['hostname']))} &bull; Scan time: {html.escape(str(system['scan_time']))}</p>
        </header>

        <main>
            <section class="score-box {score_band}">
                <div class="label">Overall Security Grade</div>
                <div class="score-number {grade_class}">{html.escape(str(overall_grade))}</div>
                <div class="score-subtitle">{overall_score}/100 weighted score</div>
                <div class="grade-description">{html.escape(str(grade_text))}</div>
            </section>

            <div class="grid" style="margin-top: 20px;">
                <div class="metric"><div class="label">Pass</div><div class="value">{status_counts.get('PASS', 0)}</div></div>
                <div class="metric"><div class="label">Review</div><div class="value">{status_counts.get('REVIEW', 0)}</div></div>
                <div class="metric"><div class="label">Fail</div><div class="value">{status_counts.get('FAIL', 0)}</div></div>
                <div class="metric"><div class="label">High Risk Items</div><div class="value">{risk_counts.get('High', 0)}</div></div>
            </div>

            <section class="card">
                <h2>System Information</h2>
                <dl>
                    <dt>Hostname</dt><dd>{html.escape(str(system['hostname']))}</dd>
                    <dt>OS</dt><dd>{html.escape(str(system['os']))}</dd>
                    <dt>OS Version</dt><dd>{html.escape(str(system['os_version']))}</dd>
                    <dt>Architecture</dt><dd>{html.escape(str(system['architecture']))}</dd>
                    <dt>Running as Admin</dt><dd>{html.escape(str(system['running_as_admin']))}</dd>
                </dl>
            </section>

            <section class="card">
                <h2>Priority Findings</h2>
                <p>These are the checks that need review or remediation first.</p>
                <div class="table-wrap">
                    <table>
                        <tr>
                            <th>Check</th>
                            <th>Status</th>
                            <th>Risk</th>
                            <th>Finding</th>
                            <th>Recommended Fix</th>
                        </tr>
                        {priority_rows}
                    </table>
                </div>
            </section>

            {category_sections}
            {raw_audit_section}
        </main>

        <footer>
            Generated by Windows Security Audit Tool. Review findings against your organization's policy before making changes.
        </footer>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as file:
        file.write(report)

def audit_threat_persistence_indicators():
    command = (
        "$tasks = Get-ScheduledTask | "
        "Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | "
        "Select-Object TaskName, TaskPath, State, Author, "
        "@{Name='Execute';Expression={$_.Actions.Execute}}, "
        "@{Name='Arguments';Expression={$_.Actions.Arguments}}; "
        "$tasks | ConvertTo-Json -Depth 4"
    )

    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result(
            "PASS",
            "No non-Microsoft scheduled tasks detected",
            10
        ), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    suspicious_keywords = [
        "powershell",
        "-enc",
        "-encodedcommand",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "regsvr32",
        "rundll32",
        "certutil",
        "bitsadmin",
        "appdata",
        "temp",
        "public",
        "downloads",
    ]

    findings = []

    for task in data:
        combined = " ".join([
            str(task.get("TaskName", "")),
            str(task.get("TaskPath", "")),
            str(task.get("Author", "")),
            str(task.get("Execute", "")),
            str(task.get("Arguments", "")),
        ]).lower()

        if any(keyword in combined for keyword in suspicious_keywords):
            findings.append(f"{task.get('TaskPath', '')}{task.get('TaskName', '')}")

    if not findings:
        return check_result(
            "PASS",
            f"{len(data)} non-Microsoft scheduled task(s) reviewed; no suspicious persistence indicators found",
            10
        ), result["stdout"]

    return check_result(
        "REVIEW",
        f"{len(findings)} suspicious persistence indicator(s) found: {', '.join(findings[:10])}",
        5
    ), result["stdout"]


def print_console_summary(data):
    overall_score = data.get("overall_score", 0)
    overall_grade = data.get("overall_grade", get_letter_grade(overall_score))

    print("")
    print("=" * 60)
    print("Windows Security Audit Summary")
    print("=" * 60)
    print(f"Overall Grade: {overall_grade}")
    print(f"Weighted Score: {overall_score}/100")
    print("")

    grouped = {
        "FAIL": [],
        "REVIEW": [],
        "PASS": [],
    }

    for check_name, check_data in data.get("checks", {}).items():
        summary = check_data.get("summary", {})
        status = summary.get("status", "REVIEW")
        message = summary.get("message", "")
        risk = summary.get("remediation", {}).get("risk", "Informational")
       

         

        grouped.setdefault(status, []).append(
            {
                "name": check_name,
                "message": message,
                "risk": risk,
            }
        )

    for status in ["FAIL", "REVIEW", "PASS"]:
        findings = grouped.get(status, [])

        if not findings:
            continue

        print(f"{status} ({len(findings)}):")

        for finding in findings:
            print(
                f"  - [{finding['risk']}] "
                f"{finding['name']}: {finding['message']}"
            )

        print("")

    print("=" * 60)
    print("")

def audit_threat_remote_access_tools():
    command = (
        "$paths = @("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        "); "
        "$apps = Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation; "
        "$apps | ConvertTo-Json -Depth 4"
    )

    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result(
            "REVIEW",
            "Remote access software inventory could not be collected",
            5
        ), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    remote_tools = [
        "anydesk",
        "rustdesk",
        "teamviewer",
        "screenconnect",
        "connectwise",
        "remote utilities",
        "ultravnc",
        "tightvnc",
        "realvnc",
        "logmein",
        "splashtop",
        "bomgar",
        "beyondtrust",
        "dwservice",
        "meshcentral",
        "atera",
    ]

    findings = []

    for app in data:
        name = str(app.get("DisplayName", "") or "")
        publisher = str(app.get("Publisher", "") or "")
        install_location = str(app.get("InstallLocation", "") or "")
        combined = f"{name} {publisher} {install_location}".lower()

        for tool in remote_tools:
            if tool in combined:
                findings.append(name or tool)
                break

    findings = sorted(set(findings))

    if not findings:
        return check_result(
            "PASS",
            "No common remote access tools detected in installed software",
            10
        ), result["stdout"]

    return check_result(
        "REVIEW",
        f"{len(findings)} remote access tool indicator(s) found: {', '.join(findings[:10])}",
        5
    ), result["stdout"]

def audit_threat_suspicious_processes():
    command = (
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId, Name, CommandLine | "
        "ConvertTo-Json -Depth 4"
    )

    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result(
            "REVIEW",
            "Unable to collect process information",
            5
        ), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    suspicious_patterns = [
        "powershell -enc",
        "powershell.exe -enc",
        "-encodedcommand",
        "frombase64string",
        "downloadstring",
        "invoke-webrequest",
        "iex ",
        "iwr ",
        "certutil",
        "bitsadmin",
        "mshta",
        "rundll32",
        "regsvr32",
        "wscript",
        "cscript",
    ]

    findings = []

    for proc in data:
        name = str(proc.get("Name", ""))
        cmdline = str(proc.get("CommandLine", "") or "")

        combined = f"{name} {cmdline}".lower()

        for pattern in suspicious_patterns:
            if pattern in combined:
                findings.append(
                    f"{name} (PID {proc.get('ProcessId')})"
                )
                break

    findings = sorted(set(findings))

    if not findings:
        return check_result(
            "PASS",
            "No suspicious process indicators detected",
            10
        ), result["stdout"]

    return check_result(
        "REVIEW",
        f"{len(findings)} suspicious process indicator(s) found: {', '.join(findings[:10])}",
        5
    ), result["stdout"]

def save_to_pdf(html_file, pdf_file):
    edge_paths = [
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ]

    edge = None

    for path in edge_paths:
        if Path(path).exists():
            edge = path
            break

    if not edge:
        raise FileNotFoundError("Microsoft Edge was not found. Cannot generate PDF.")

    subprocess.run(
        [
            edge,
            "--headless",
            "--disable-gpu",
            f"--print-to-pdf={pdf_file}",
            str(html_file),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

def audit_threat_network_connections():
    command = (
        "Get-NetTCPConnection -State Established | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | "
        "ConvertTo-Json -Depth 4"
    )

    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result(
            "REVIEW",
            "Unable to collect network connections",
            5
        ), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    suspicious_ports = {
        4444, 5555, 8080, 8443, 1337, 9001
    }

    findings = []

    for conn in data:
        remote = str(conn.get("RemoteAddress", ""))

        if (
            remote.startswith("127.")
            or remote.startswith("10.")
            or remote.startswith("192.168.")
            or remote.startswith("172.16.")
            or remote == "::1"
        ):
            continue

        try:
            port = int(conn.get("RemotePort", 0))
        except:
            port = 0

        if port in suspicious_ports:
            findings.append(
                f"{remote}:{port} (PID {conn.get('OwningProcess')})"
            )

    if not findings:
        return check_result(
            "PASS",
            "No suspicious external network connections detected",
            10
        ), result["stdout"]

    return check_result(
        "REVIEW",
        f"{len(findings)} suspicious connection(s) detected",
        5
    ), "\n".join(findings)

def test_remote_connectivity(host, timeout=15):
    command = f'Test-WsMan "{host}" -ErrorAction Stop'

    result = run_powershell(command, timeout=timeout)

    return result.get("ok") is True

def run_remote_audit(host):
    command = f"""
    Invoke-Command -ComputerName "{host}" -ScriptBlock {{
        hostname
    }}
    """

    return run_powershell(command, timeout=60)

def load_fleet_targets(fleet_file):
    with open(fleet_file, "r") as f:
        return [
            line.strip()
            for line in f
            if line.strip()
        ]
def save_fleet_report(results, filename):
    report = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "total_systems": len(results),
        "audited": sum(1 for r in results if r.get("status") == "AUDITED"),
        "failed": sum(1 for r in results if r.get("status") == "FAILED"),
        "systems": results,
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)


def run_remote_mini_audit(host):
    command = f"""
    Invoke-Command -ComputerName "{host}" -ScriptBlock {{

        $firewallProfiles = Get-NetFirewallProfile
        $firewallEnabled = ($firewallProfiles | Where-Object {{ $_.Enabled -eq $true }}).Count -ge 3

        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $defenderEnabled = $false

        if ($defenderStatus) {{
            $defenderEnabled = $defenderStatus.AntivirusEnabled -eq $true
        }}

        $bitlockerEnabled = $false
        $bitlocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue

        if ($bitlocker) {{
            $bitlockerEnabled = $bitlocker.ProtectionStatus -eq "On" -or $bitlocker.ProtectionStatus -eq 1
        }}

        $lastUpdate = Get-HotFix |
            Where-Object {{ $_.InstalledOn }} |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 1

        [PSCustomObject]@{{
            Hostname = $env:COMPUTERNAME
            FirewallEnabled = $firewallEnabled
            DefenderEnabled = $defenderEnabled
            BitLockerEnabled = $bitlockerEnabled
            LastUpdate = if ($lastUpdate) {{ $lastUpdate.InstalledOn.ToString("yyyy-MM-dd") }} else {{ $null }}
        }}

    }} | ConvertTo-Json -Depth 4
    """

    result = run_powershell(command, timeout=90)

    if not result.get("ok"):
        return None

    return parse_json_output(result)


def score_remote_system(data):
    score = 0

    if data.get("FirewallEnabled"):
        score += 30

    if data.get("DefenderEnabled"):
        score += 30

    if data.get("BitLockerEnabled"):
        score += 30

    if data.get("LastUpdate"):
        score += 10

    return score




def run_fleet_scan(fleet_file):
    hosts = load_fleet_targets(fleet_file)
    results = []

    for host in hosts:
        print(f"[{host}] Testing connectivity...")

        if not test_remote_connectivity(host):
            print(f"[{host}] FAILED - WinRM unavailable")

            results.append({
                "host": host,
                "status": "FAILED",
                "reason": "WinRM unavailable"
            })

            continue

        print(f"[{host}] Reachable")

        audit_data = run_remote_mini_audit(host)

        if audit_data:
            score = score_remote_system(audit_data)

            findings = []

            if not audit_data.get("FirewallEnabled"):
                findings.append("Firewall Disabled")

            if not audit_data.get("DefenderEnabled"):
                findings.append("Defender Disabled")

            if not audit_data.get("BitLockerEnabled"):
                findings.append("BitLocker Disabled")

            if not audit_data.get("LastUpdate"):
                findings.append("Missing Last Update")

            results.append({
                "host": host,
                "status": "AUDITED",
                "score": score,
                "grade": get_letter_grade(score),
                "findings": findings
            })

        else:
            results.append({
                "host": host,
                "status": "FAILED",
                "reason": "Audit failed"
            })

    return results
def save_fleet_dashboard(results, filename):

    total = len(results)
    audited = sum(1 for r in results if r.get("status") == "AUDITED")
    failed = sum(1 for r in results if r.get("status") == "FAILED")

    scores = [
        r.get("score")
        for r in results
        if r.get("status") == "AUDITED" and isinstance(r.get("score"), int)
    ]

    average_score = round(sum(scores) / len(scores)) if scores else 0
    organization_grade = get_letter_grade(average_score) if scores else "N/A"

    # Grade Distribution
    a_count = sum(1 for r in results if r.get("grade") == "A")
    b_count = sum(1 for r in results if r.get("grade") == "B")
    c_count = sum(1 for r in results if r.get("grade") == "C")
    d_count = sum(1 for r in results if r.get("grade") == "D")
    f_count = sum(1 for r in results if r.get("grade") == "F")

    # Most Common Findings
    finding_counts = {
        "Firewall Disabled": 0,
        "Defender Disabled": 0,
        "BitLocker Disabled": 0,
        "Missing Last Update": 0,
    }

    for result in results:
        if result.get("status") != "AUDITED":
            continue

        for finding in result.get("findings", []):
            if finding in finding_counts:
                finding_counts[finding] += 1

    common_findings_rows = ""

    for finding, count in sorted(
        finding_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        if count == 0:
            continue

        common_findings_rows += f"""
        <tr>
            <td>{html.escape(finding)}</td>
            <td>{count}</td>
        </tr>
        """

    if not common_findings_rows:
        common_findings_rows = """
        <tr>
            <td colspan="2">No common findings detected.</td>
        </tr>
        """

    # Sort Worst Systems First
    ranked_results = sorted(
        results,
        key=lambda x: x.get("score", 0)
        if x.get("status") == "AUDITED"
        else -1
    )

    # Top Risk Systems
    top_risk_rows = ""

    for result in ranked_results[:10]:

        if result.get("status") != "AUDITED":
            continue

        top_risk_rows += f"""
        <tr>
            <td>{html.escape(str(result.get('host', '')))}</td>
            <td>{html.escape(str(result.get('grade', '-')))}</td>
            <td>{html.escape(str(result.get('score', '-')))}</td>
        </tr>
        """

    def grade_class_for(result):

        if result.get("status") == "FAILED":
            return "grade-f"

        return {
            "A": "grade-a",
            "B": "grade-b",
            "C": "grade-c",
            "D": "grade-d",
            "F": "grade-f",
        }.get(result.get("grade", ""), "")

    rows = ""

    for result in ranked_results:

        host = html.escape(str(result.get("host", "")))
        status = html.escape(str(result.get("status", "")))
        grade = html.escape(str(result.get("grade", "-")))
        score = html.escape(str(result.get("score", "-")))
        reason = html.escape(str(result.get("reason", "")))

        status_class = {
            "AUDITED": "pass",
            "ONLINE": "review",
            "FAILED": "fail"
        }.get(result.get("status"), "fail")

        row_class = grade_class_for(result)

        rows += f"""
        <tr class="{row_class}">
            <td>{host}</td>
            <td><span class="badge {status_class}">{status}</span></td>
            <td>{grade}</td>
            <td>{score}</td>
            <td>{reason}</td>
        </tr>
        """

    dashboard = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Fleet Security Dashboard</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #f5f7fb;
    color: #1f2937;
    margin: 0;
}}

header {{
    background: #111827;
    color: white;
    padding: 24px;
}}

main {{
    padding: 24px;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
}}

.card {{
    background: white;
    border: 1px solid #d8dee9;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 20px;
}}

.label {{
    color: #6b7280;
    font-size: 12px;
    text-transform: uppercase;
    font-weight: bold;
}}

.value {{
    font-size: 30px;
    font-weight: bold;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    border-bottom: 1px solid #d8dee9;
    padding: 10px;
    text-align: left;
}}

th {{
    background: #f3f4f6;
}}

.badge {{
    color: white;
    border-radius: 999px;
    padding: 4px 10px;
    font-size: 12px;
    font-weight: bold;
}}

.pass {{
    background: #15803d;
}}

.review {{
    background: #b45309;
}}

.fail {{
    background: #b91c1c;
}}

.grade-a {{
    background: #dcfce7;
}}

.grade-b {{
    background: #ecfdf5;
}}

.grade-c {{
    background: #fef9c3;
}}

.grade-d {{
    background: #ffedd5;
}}

.grade-f {{
    background: #fee2e2;
}}

</style>
</head>

<body>

<header>
    <h1>Fleet Security Dashboard</h1>
</header>

<main>

<div class="grid">

<div class="card">
<div class="label">Total Systems</div>
<div class="value">{total}</div>
</div>

<div class="card">
<div class="label">Audited</div>
<div class="value">{audited}</div>
</div>

<div class="card">
<div class="label">Failed</div>
<div class="value">{failed}</div>
</div>

<div class="card">
<div class="label">Average Score</div>
<div class="value">{average_score}</div>
</div>

<div class="card">
<div class="label">Organization Grade</div>
<div class="value">{organization_grade}</div>
</div>

<div class="card">
<div class="label">A Systems</div>
<div class="value">{a_count}</div>
</div>

<div class="card">
<div class="label">B Systems</div>
<div class="value">{b_count}</div>
</div>

<div class="card">
<div class="label">C Systems</div>
<div class="value">{c_count}</div>
</div>

<div class="card">
<div class="label">D Systems</div>
<div class="value">{d_count}</div>
</div>

<div class="card">
<div class="label">F Systems</div>
<div class="value">{f_count}</div>
</div>

</div>

<section class="card">
<h2>Top Risk Systems</h2>
<table>
<tr>
<th>Host</th>
<th>Grade</th>
<th>Score</th>
</tr>
{top_risk_rows}
</table>
</section>

<section class="card">
<h2>Most Common Findings</h2>
<table>
<tr>
<th>Finding</th>
<th>Affected Systems</th>
</tr>
{common_findings_rows}
</table>
</section>

<section class="card">
<h2>Fleet Results</h2>
<table>
<tr>
<th>Host</th>
<th>Status</th>
<th>Grade</th>
<th>Score</th>
<th>Reason</th>
</tr>
{rows}
</table>
</section>

</main>
</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(dashboard)
        
def run_remote_mini_audit(host):
        command = f"""
    Invoke-Command -ComputerName "{host}" -ScriptBlock {{

        $firewall = (Get-NetFirewallProfile |
            Where-Object {{ $_.Enabled -eq $true }}).Count

        $defender = (Get-MpComputerStatus).AntivirusEnabled

        $bitlocker = (
            Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        ).ProtectionStatus

        $updates = (
            Get-HotFix |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 1
        ).InstalledOn

        [PSCustomObject]@{{
            Hostname = $env:COMPUTERNAME
            FirewallEnabled = ($firewall -gt 0)
            DefenderEnabled = $defender
            BitLockerEnabled = ($bitlocker -eq 1)
            LastUpdate = $updates
        }}

    }} | ConvertTo-Json -Depth 4
    """

        result = run_powershell(command, timeout=90)

        if not result.get("ok"):
            return None

        return parse_json_output(result)

def score_remote_system(data):
    score = 0

    if data.get("FirewallEnabled"):
        score += 30

    if data.get("DefenderEnabled"):
        score += 30

    if data.get("BitLockerEnabled"):
        score += 30

    if data.get("LastUpdate"):
        score += 10

    return score

def save_basline(report, filename):
    baseline = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "system": report.get("system", {}),
        "overall_score": report.get("overall_score", 0),
        "overall_grade": report.get("overall_grade", "N/A"),
        "checks": {}
    }

    for check_name, check_data in report.get("checks", {}).items():
        summary = check_data.get("summary", {})

        baseline["checks"][check_name] = {
            "status": summary.get("status", "REVIEW"),
            "score": summary.get("score", 0),
            "message": summary.get("message", ""),
            "risk": summary.get("remediation", {}).get("risk", "Informational")
        }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=4)

def compare_with_baseline(current_report, baseline_file):
    with open(baseline_file, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    changes = {
        "score_change": current_report.get("overall_score", 0) - baseline.get("overall_score", 0),
        "grade_before": baseline.get("overall_grade", "N/A"),
        "grade_after": current_report.get("overall_grade", "N/A"),
        "new_checks": [],
        "removed_checks": [],
        "changed_checks": [],
    }

    current_checks = current_report.get("checks", {})
    baseline_checks = baseline.get("checks", {})

    for check_name, current_data in current_checks.items():
        current_status = current_data.get("summary", {}).get("status", "REVIEW")
        baseline_status = baseline_checks.get(check_name, {}).get("status", "REVIEW")

        if current_status != baseline_status:
            if current_status in ["FAIL", "REVIEW"] and baseline_status == "PASS":
                changes["new_findings"].append(check_name)
            elif current_status == "PASS" and baseline_status in ["FAIL", "REVIEW"]:
                changes["resolved_findings"].append(check_name)

    changes["score_change"] = current_report.get("overall_score", 0) - baseline.get("overall_score", 0)
    changes["grade_change"] = (
        (current_report.get("overall_grade") or "") + " -> " + (baseline.get("overall_grade") or "")
    )

    return changes

def save_drift_report(changes, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(changes, f, indent=4)

def save_drift_html_report(changes, filename):
    score_change = changes.get("score_change", 0)
    grade_before = changes.get("grade_before", "N/A")
    grade_after = changes.get("grade_after", "N/A")

    if score_change > 0:
        trend = "Improved"
        trend_class = "good"
    elif score_change < 0:
        trend = "Worsened"
        trend_class = "bad"
    else:
        trend = "No Change"
        trend_class = "neutral"

    changed_rows = ""

    for item in changes.get("changed_checks", []):
        changed_rows += f"""
        <tr>
            <td>{html.escape(str(item.get("check", "")))}</td>
            <td>{html.escape(str(item.get("old_status", "")))}</td>
            <td>{html.escape(str(item.get("new_status", "")))}</td>
            <td>{html.escape(str(item.get("old_score", "")))}</td>
            <td>{html.escape(str(item.get("new_score", "")))}</td>
            <td>{html.escape(str(item.get("new_message", "")))}</td>
        </tr>
        """

    if not changed_rows:
        changed_rows = """
        <tr>
            <td colspan="6">No changed checks detected.</td>
        </tr>
        """

    new_rows = ""

    for check in changes.get("new_checks", []):
        new_rows += f"""
        <tr>
            <td>{html.escape(str(check))}</td>
        </tr>
        """

    if not new_rows:
        new_rows = """
        <tr>
            <td>No new checks detected.</td>
        </tr>
        """

    removed_rows = ""

    for check in changes.get("removed_checks", []):
        removed_rows += f"""
        <tr>
            <td>{html.escape(str(check))}</td>
        </tr>
        """

    if not removed_rows:
        removed_rows = """
        <tr>
            <td>No removed checks detected.</td>
        </tr>
        """

    html_report = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Security Drift Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f5f7fb;
                color: #1f2937;
                margin: 0;
            }}

            header {{
                background: #111827;
                color: white;
                padding: 28px 40px;
            }}

            main {{
                padding: 28px 40px;
            }}

            .grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 16px;
                margin-bottom: 20px;
            }}

            .card {{
                background: white;
                border: 1px solid #d8dee9;
                border-radius: 12px;
                padding: 18px;
                margin-bottom: 20px;
            }}

            .label {{
                color: #6b7280;
                font-size: 13px;
                text-transform: uppercase;
                font-weight: bold;
            }}

            .value {{
                font-size: 34px;
                font-weight: bold;
                margin-top: 6px;
            }}

            .good {{
                color: #15803d;
            }}

            .bad {{
                color: #b91c1c;
            }}

            .neutral {{
                color: #6b7280;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
            }}

            th, td {{
                border-bottom: 1px solid #d8dee9;
                padding: 10px;
                text-align: left;
                vertical-align: top;
            }}

            th {{
                background: #f3f4f6;
                text-transform: uppercase;
                font-size: 13px;
            }}
        </style>
    </head>
    <body>
        <header>
            <h1>Security Drift Report</h1>
            <p>Generated: {datetime.now().isoformat(timespec="seconds")}</p>
        </header>

        <main>
            <div class="grid">
                <div class="card">
                    <div class="label">Trend</div>
                    <div class="value {trend_class}">{trend}</div>
                </div>

                <div class="card">
                    <div class="label">Score Change</div>
                    <div class="value">{score_change:+}</div>
                </div>

                <div class="card">
                    <div class="label">Grade Before</div>
                    <div class="value">{html.escape(str(grade_before))}</div>
                </div>

                <div class="card">
                    <div class="label">Grade After</div>
                    <div class="value">{html.escape(str(grade_after))}</div>
                </div>
            </div>

            <section class="card">
                <h2>Changed Checks</h2>
                <table>
                    <tr>
                        <th>Check</th>
                        <th>Old Status</th>
                        <th>New Status</th>
                        <th>Old Score</th>
                        <th>New Score</th>
                        <th>Current Finding</th>
                    </tr>
                    {changed_rows}
                </table>
            </section>

            <section class="card">
                <h2>New Checks</h2>
                <table>
                    <tr>
                        <th>Check</th>
                    </tr>
                    {new_rows}
                </table>
            </section>

            <section class="card">
                <h2>Removed Checks</h2>
                <table>
                    <tr>
                        <th>Check</th>
                    </tr>
                    {removed_rows}
                </table>
            </section>
        </main>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_report)

def main():
    args = parse_arguments()

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    if args.fleet:
        fleet_results = run_fleet_scan(args.fleet)

        fleet_report_path = output_dir / "fleet_report.json"

        save_fleet_report(
            fleet_results,
            fleet_report_path
        )
        fleet_dashboard_path = output_dir / "fleet_dashboard.html"

        save_fleet_dashboard(
        fleet_results,
        fleet_dashboard_path
)

        print("\nFleet Summary")
        print("=" * 50)

        for result in fleet_results:
            print(
                f"{result['host']} : "
                f"{result['status']}"
            )

        print(f"\nFleet report saved to: {fleet_report_path.resolve()}")
        print(f"Fleet dashboard saved to: {fleet_dashboard_path.resolve()}")

        return
    
    if not any([args.html, args.csv, args.json, args.pdf, args.summary]):
        args.html = True
        args.csv = True
        args.json = True
        args.pdf = True
        
    checks = {}

    audit_functions = {
        "Firewall": audit_firewall,
        "Microsoft Defender": audit_defender,
        "Defender Signatures": audit_defender_signatures,
        "BitLocker": audit_bitlocker,
        "BitLocker All Volumes": audit_bitlocker_all_volumes,
        "Windows Update": audit_windows_update,
        "Windows Update Age": audit_windows_update_age,
        "RDP": audit_rdp,
        "SMB": audit_smb,
        "UAC": audit_uac,
        "Secure Boot / TPM": audit_secure_boot_tpm,
        "Event Logging": audit_event_logging,
        "Installed Software": audit_installed_software,
        "Vulnerable Software Detection": audit_vulnerable_software,
        "Scheduled Tasks": audit_scheduled_tasks,
        "Autorun Registry Keys": audit_autoruns_registry,
        "Startup Folders": audit_startup_folders,
        "Windows Services": audit_windows_services,
        "Local Administrators": audit_local_admins,
        "Local Users": audit_local_users,
        "Password Policy": audit_password_policy,
        "Failed Logins": audit_failed_logins,
        "Network Shares": audit_network_shares,
        "Share Permissions": audit_share_permissions,
        "LSA / Credential Guard": audit_lsa_credential_guard,
        "Defender ASR Rules": audit_defender_asr_rules,
        "Listening Connections": audit_listening_connections,
        "PowerShell Security": audit_powershell_security,
        "USB Storage": audit_usb_storage,
        
    }
    if args.hunt:
        audit_functions.update({
        "Threat Hunt - Remote Access Tools": audit_threat_remote_access_tools,
        "Threat Hunt - Suspicious Processes": audit_threat_suspicious_processes,
        "Threat Hunt - Persistence Indicators": audit_threat_persistence_indicators,
        "Threat Hunt - Network Connections": audit_threat_network_connections,
    })


    
    for name, function in audit_functions.items():
        if not args.quiet:
            print(f"Running check: {name}")

        try:
            summary, raw = function()
        except Exception as e:
            summary = check_result("REVIEW", f"Check failed unexpectedly: {e}", 5)
            raw = str(e)

        checks[name] = {
            "summary": summary,
            "raw": raw,
        }

    weighted_score = 0
    max_weighted_score = 0

    for check_name, check_data in checks.items():
        weight = CHECK_WEIGHTS.get(check_name, 5)
        raw_score = check_data["summary"]["score"]

        weighted_score += raw_score * weight
        max_weighted_score += 10 * weight

        check_data["summary"]["weight"] = weight
        check_data["summary"]["remediation"] = get_remediation(
            check_name,
            check_data["summary"].get("status", "REVIEW")
        )
        check_data["summary"]["mitre"] = get_mitre_mapping(check_name)

    overall_score = round((weighted_score / max_weighted_score) * 100)
    overall_grade = get_letter_grade(overall_score)

    report = {
        "system": get_system_info(),
        "overall_score": overall_score,
        "overall_grade": overall_grade,
        "checks": checks,
    }

    if args.json:
        save_to_json(report, output_dir / "audit_report.json")

    if args.csv:
        save_to_csv(report, output_dir / "audit_results.csv")

    html_path = output_dir / "audit_report.html"
    executive_html_path = output_dir / "audit_report_executive.html"
    pdf_path = output_dir / "audit_report.pdf"

    if args.html:
        save_to_html(report, html_path, include_raw=True)

    if args.pdf:
        try:
            save_to_html(report, executive_html_path, include_raw=False)
            save_to_pdf(
                executive_html_path.resolve(),
                pdf_path.resolve()
            )
            print(f"PDF created: {pdf_path.resolve()}")
        except Exception as e:
            print(f"PDF export failed: {e}")

    if args.summary:
        print_console_summary(report)

    if not args.quiet:
        print("Audit complete.")
        print(f"Overall score: {overall_score}/100")
        print(f"Reports saved in: {output_dir.resolve()}")

    if args.baseline:
        baseline_path = output_dir / "baseline.json"
        save_basline(report, baseline_path)
        print(f"Baseline saved to: {baseline_path.resolve()}")

    if args.compare:
        drift = compare_with_baseline(report, args.compare)

    drift_json_path = output_dir / "drift_report.json"
    drift_html_path = output_dir / "drift_report.html"

    if args.compare:
        save_drift_report(drift, drift_json_path)
        save_drift_html_report(drift, drift_html_path)

        print(f"Drift JSON report saved to: {drift_json_path.resolve()}")
        print(f"Drift HTML report saved to: {drift_html_path.resolve()}")

if __name__ == "__main__":
    main()
