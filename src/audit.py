import platform
import csv
import json
import html
import ctypes
import subprocess
from datetime import datetime
from pathlib import Path

# Constants
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"




REPORT_DIR = Path("audit_output")
REPORT_DIR.mkdir(exist_ok=True)


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def audit_event_logging():
    result = run_powershell(
        "auditpol /get /category:*"
    )

    output = result["stdout"]

    if not output:
        return check_result(
            "REVIEW",
            "Audit policy could not be verified",
            5
        ), output

    important_categories = [
        "Logon",
        "Account Logon",
        "Account Management",
        "Policy Change",
        "Privilege Use"
    ]

    missing = []

    for category in important_categories:
        if category not in output:
            missing.append(category)

    if not missing:
        return check_result(
            "PASS",
            "Critical audit categories detected",
            10
        ), output

    return check_result(
        "REVIEW",
        f"Could not verify: {', '.join(missing)}",
        6
    ), output

def audit_windows_update():
    command = (
        "$session = New-Object -ComObject Microsoft.Update.Session; "
        "$searcher = $session.CreateUpdateSearcher(); "
        "$historyCount = $searcher.GetTotalHistoryCount(); "
        "$history = $searcher.QueryHistory(0, [Math]::Min(10, $historyCount)) | "
        "Select-Object Date, Title, ResultCode; "
        "$pending = $searcher.Search('IsInstalled=0 and Type=''Software''').Updates.Count; "
        "[PSCustomObject]@{ "
        "PendingUpdates = $pending; "
        "RecentHistory = $history "
        "} | ConvertTo-Json -Depth 4"
    )

    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Windows Update status could not be verified", 5), result["stdout"]

    pending = data.get("PendingUpdates", None)

    if pending is None:
        return check_result("REVIEW", "Pending update count could not be determined", 5), result["stdout"]

    if pending == 0:
        return check_result("PASS", "No pending Windows software updates found", 10), result["stdout"]

    if pending <= 5:
        return check_result("REVIEW", f"{pending} pending Windows update(s) found", 6), result["stdout"]

    return check_result("FAIL", f"{pending} pending Windows update(s) found", 2), result["stdout"]

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
        return {
            "ok": False,
            "stdout": "",
            "stderr": "",
            "error": "Command timed out",
        }
    except Exception as e:
        return {
            "ok": False,
            "stdout": "",
            "stderr": "",
            "error": str(e),
        }


def parse_json_output(result):
    if not result["ok"]:
        return None

    try:
        return json.loads(result["stdout"])
    except Exception:
        return None


def check_result(status, message, score):
    return {
        "status": status,
        "message": message,
        "score": score,
    }


def get_system_info():
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "running_as_admin": is_admin(),
    }
def audit_smb():
    command = (
        "$smb = Get-SmbServerConfiguration | "
        "Select-Object EnableSMB1Protocol, EnableSMB2Protocol, "
        "RequireSecuritySignature, EnableSecuritySignature, "
        "EnableInsecureGuestLogons; "
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

def audit_rdp():
    command = (
        "$rdp = Get-ItemProperty "
        "-Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
        "-Name fDenyTSConnections; "
        "$nla = Get-ItemProperty "
        "-Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "-Name UserAuthentication; "
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
def audit_firewall():
    result = run_powershell(
        "Get-NetFirewallProfile | "
        "Select-Object Name, Enabled | ConvertTo-Json"
    )

    data = parse_json_output(result)

    if not data:
        return check_result("REVIEW", "Firewall status could not be verified", 5), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    disabled = [p["Name"] for p in data if not p.get("Enabled")]

    if not disabled:
        return check_result("PASS", "All firewall profiles are enabled", 10), result["stdout"]

    return check_result(
        "FAIL",
        f"Disabled firewall profiles: {', '.join(disabled)}",
        0,
    ), result["stdout"]


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

    return check_result(
        "FAIL",
        f"Defender issues detected: {', '.join(failures)}",
        0,
    ), result["stdout"]


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


def audit_bitlocker():
    result = run_powershell("manage-bde -status C:")

    output = result["stdout"]

    if "Protection Status:    Protection On" in output:
        return check_result("PASS", "BitLocker protection is enabled on C:", 10), output

    if "Protection Status:    Protection Off" in output:
        return check_result("FAIL", "BitLocker protection is off on C:", 0), output

    return check_result("REVIEW", "BitLocker status is unclear", 5), output


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
    result = run_powershell(
        'wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:10 /f:text'
    )

    output = result["stdout"]

    if "No events were found" in output:
        return check_result("PASS", "No recent failed login events found", 10), output

    if "Event ID: 4625" in output:
        count = output.count("Event ID: 4625")
        return check_result("REVIEW", f"{count} recent failed login event(s) found", 5), output

    return check_result("REVIEW", "Failed login status could not be verified", 5), output


def save_to_json(data, filename):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def save_to_csv(data, filename):
    flat = {
        "hostname": data["system"]["hostname"],
        "scan_time": data["system"]["scan_time"],
        "running_as_admin": data["system"]["running_as_admin"],
        "overall_score": data["overall_score"],
    }

    for check_name, check_data in data["checks"].items():
        flat[f"{check_name}_status"] = check_data["summary"]["status"]
        flat[f"{check_name}_message"] = check_data["summary"]["message"]
        flat[f"{check_name}_score"] = check_data["summary"]["score"]

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=flat.keys())
        writer.writeheader()
        writer.writerow(flat)

def audit_uac():
    command = (
        "$uac = Get-ItemProperty "
        "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; "
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
        "TpmEnabled = $tpm.TpmEnabled; "
        "} | ConvertTo-Json"
    )

    result = run_powershell(command)
    data = parse_json_output(result)

    if not data:
        return check_result(
            "REVIEW",
            "Secure Boot / TPM status could not be verified",
            5
        ), result["stdout"]

    issues = []

    if not data.get("SecureBootEnabled"):
        issues.append("Secure Boot disabled")

    if not data.get("TpmPresent"):
        issues.append("TPM not present")

    if data.get("TpmPresent") and not data.get("TpmReady"):
        issues.append("TPM not ready")

    if not issues:
        return check_result(
            "PASS",
            "Secure Boot enabled and TPM ready",
            10
        ), result["stdout"]

    if "TPM not present" in issues:
        return check_result(
            "FAIL",
            "; ".join(issues),
            0
        ), result["stdout"]

    return check_result(
        "REVIEW",
        "; ".join(issues),
        5
    ), result["stdout"]

def save_to_html(data, filename):
    rows = ""

    for name, check in data["checks"].items():
        status = html.escape(check["summary"]["status"])
        message = html.escape(check["summary"]["message"])
        score = check["summary"]["score"]
        css_class = status.lower()

        rows += f"""
        <tr>
            <td>{html.escape(name)}</td>
            <td class="{css_class}">{status}</td>
            <td>{message}</td>
            <td>{score}/10</td>
        </tr>
        """

    raw_sections = ""

    for name, check in data["checks"].items():
        raw_sections += f"""
        <h3>{html.escape(name)}</h3>
        <pre>{html.escape(check["raw"])}</pre>
        """

    system = data["system"]

    report = f"""
    <html>
    <head>
        <title>Windows Security Audit Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin-bottom: 25px;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 10px;
                text-align: left;
                vertical-align: top;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            .pass {{
                color: green;
                font-weight: bold;
            }}
            .fail {{
                color: red;
                font-weight: bold;
            }}
            .review {{
                color: orange;
                font-weight: bold;
            }}
            pre {{
                white-space: pre-wrap;
                background-color: #f8f8f8;
                padding: 10px;
                border: 1px solid #ddd;
            }}
        </style>
    </head>
    <body>
        <h1>Windows Security Audit Report</h1>

        <h2>System Information</h2>
        <table>
            <tr><th>Hostname</th><td>{html.escape(str(system["hostname"]))}</td></tr>
            <tr><th>OS</th><td>{html.escape(str(system["os"]))}</td></tr>
            <tr><th>OS Version</th><td>{html.escape(str(system["os_version"]))}</td></tr>
            <tr><th>Architecture</th><td>{html.escape(str(system["architecture"]))}</td></tr>
            <tr><th>Scan Time</th><td>{html.escape(str(system["scan_time"]))}</td></tr>
            <tr><th>Running as Admin</th><td>{html.escape(str(system["running_as_admin"]))}</td></tr>
        </table>

        <h2>Overall Score: {data["overall_score"]}/100</h2>

        <h2>Security Summary</h2>
        <table>
            <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Message</th>
                <th>Score</th>
            </tr>
            {rows}
        </table>

        <h2>Raw Audit Data</h2>
        {raw_sections}
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as file:
        file.write(report)

def audit_defender_signatures():
    result = run_powershell(
        "Get-MpComputerStatus | "
        "Select-Object "
        "AntivirusSignatureLastUpdated,"
        "AMEngineVersion,"
        "AMProductVersion,"
        "QuickScanAge,"
        "FullScanAge | ConvertTo-Json"
    )

    data = parse_json_output(result)
    

    data = parse_json_output(result)

    if not data:
        return check_result(
            "REVIEW",
            "Defender signature status could not be verified",
            5
        ), result["stdout"]

    try:
        sig_date = datetime.fromisoformat(
            data["AntivirusSignatureLastUpdated"].replace("Z", "")
        )

        age_days = (datetime.now() - sig_date).days

        full_scan_age = data.get("FullScanAge", "Unknown")

        if age_days <= 3:
            return check_result(
                "PASS",
                f"Signatures are {age_days} day(s) old. Full scan age: {full_scan_age} day(s).",
                10
            ), result["stdout"]

        if age_days <= 7:
            return check_result(
                "REVIEW",
                f"Signatures are {age_days} day(s) old. Consider updating.",
                6
            ), result["stdout"]

        return check_result(
            "FAIL",
            f"Signatures are {age_days} day(s) old.",
            0
        ), result["stdout"]

    except Exception as e:
        return check_result(
            "REVIEW",
            f"Could not calculate signature age: {e}",
            5
        ), result["stdout"]

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
        return check_result(
            "REVIEW",
            "Installed software inventory could not be verified",
            5
        ), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    risky_keywords = [
        "teamviewer",
        "anydesk",
        "vnc",
        "ultravnc",
        "tightvnc",
        "logmein",
        "screenconnect",
        "connectwise",
        "splashtop",
        "java",
        "utorrent",
        "bittorrent",
        "wireshark",
        "nmap"
    ]

    flagged = []

    for app in data:
        name = str(app.get("DisplayName", "")).lower()

        for keyword in risky_keywords:
            if keyword in name:
                flagged.append(app.get("DisplayName"))
                break

    if not flagged:
        return check_result(
            "PASS",
            f"{len(data)} installed application(s) reviewed; no risky software keywords found",
            10
        ), result["stdout"]

    return check_result(
        "REVIEW",
        f"{len(flagged)} potentially risky application(s) found: {', '.join(flagged[:10])}",
        5
    ), result["stdout"]
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
        return check_result(
            "REVIEW",
            "Scheduled tasks could not be verified",
            5
        ), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    suspicious_keywords = [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "bitsadmin",
        "certutil",
        "appdata",
        "temp",
        "public",
        "downloads"
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

        for keyword in suspicious_keywords:
            if keyword in combined:
                flagged.append(
                    f"{task.get('TaskPath', '')}{task.get('TaskName', '')}"
                )
                break

    if not flagged:
        return check_result(
            "PASS",
            f"{len(data)} non-Microsoft scheduled task(s) reviewed; no suspicious keywords found",
            10
        ), result["stdout"]

    return check_result(
        "REVIEW",
        f"{len(flagged)} suspicious scheduled task(s) found: {', '.join(flagged[:10])}",
        5
    ), result["stdout"]

def audit_startup_folders():
    command = (
        "$paths = @("
        "[Environment]::GetFolderPath('Startup'),"
        "[Environment]::GetFolderPath('CommonStartup')"
        "); "
        "$items = foreach ($path in $paths) { "
        "if (Test-Path $path) { "
        "Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue | "
        "Select-Object @{Name='StartupPath';Expression={$path}}, "
        "Name, FullName, Extension, Length, LastWriteTime "
        "} "
        "}; "
        "$items | ConvertTo-Json -Depth 4"
    )

    result = run_powershell(command, timeout=60)
    data = parse_json_output(result)

    if not data:
        return check_result(
            "PASS",
            "No startup folder items found",
            10
        ), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    suspicious_extensions = [
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".bat",
        ".cmd",
        ".scr",
        ".hta",
        ".lnk",
        ".exe"
    ]

    flagged = []

    for item in data:
        extension = str(item.get("Extension", "")).lower()
        full_name = str(item.get("FullName", "")).lower()

        if extension in suspicious_extensions:
            flagged.append(item.get("FullName"))
            continue

        if "appdata" in full_name or "temp" in full_name:
            flagged.append(item.get("FullName"))

    if not flagged:
        return check_result(
            "PASS",
            f"{len(data)} startup folder item(s) reviewed; no suspicious items found",
            10
        ), result["stdout"]

    return check_result(
        "REVIEW",
        f"{len(flagged)} suspicious startup folder item(s) found: {', '.join(flagged[:10])}",
        5
    ), result["stdout"]

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
        return check_result(
            "PASS",
            f"{len(flagged)} suspicious autorun entry/entries found: {', '.join(flagged[:10])}",
                    ), result["stdout"]

    if isinstance(data, dict):
        data = [data]

    suspicious_keywords = [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "bitsadmin",
        "certutil",
        "appdata",
        "temp",
        "public",
        "downloads",
        "startup",
        ".ps1",
        ".vbs",
        ".js",
        ".bat",
        ".cmd",
        ".scr"
    ]

    flagged = []

    for item in data:
        combined = " ".join([
            str(item.get("RegistryPath", "")),
            str(item.get("Name", "")),
            str(item.get("Value", "")),
        ]).lower()

        for keyword in suspicious_keywords:
            if keyword in combined:
                flagged.append(
                    f"{item.get('RegistryPath')}\\{item.get('Name')}"
                )
                break

    if not flagged:
        return check_result(
            "PASS",
            f"{len(data)} autorun registry entrie(s) reviewed; no suspicious keywords found",
            10
        ), result["stdout"]

    return check_result(
        "REVIEW",
        f"{len(flagged)} suspicious autorun entrie(s) found: {', '.join(flagged[:10])}",
        5
    ), result["stdout"]

def main():
    checks = {}

    audit_functions = {
        "Firewall": audit_firewall,
        "Microsoft Defender": audit_defender,
        "Defender Signatures": audit_defender_signatures,
        "BitLocker": audit_bitlocker,
        "Windows Update": audit_windows_update,
        "Installed Software": audit_installed_software,
        "RDP": audit_rdp,
        "SMB": audit_smb,
        "UAC": audit_uac,
        "Secure Boot / TPM": audit_secure_boot_tpm,
        "Event Logging": audit_event_logging,
        "Scheduled Tasks": audit_scheduled_tasks,
        "Autorun Registry Keys": audit_autoruns_registry,
        "Startup Folders": audit_startup_folders,
}

    for name, function in audit_functions.items():
        summary, raw = function()
        checks[name] = {
            "summary": summary,
            "raw": raw,
        }

    total_score = sum(check["summary"]["score"] for check in checks.values())
    max_score = len(checks) * 10
    overall_score = round((total_score / max_score) * 100)

    report = {
        "system": get_system_info(),
        "overall_score": overall_score,
        "checks": checks,
    }

    save_to_json(report, REPORT_DIR / "audit_report.json")
    save_to_csv(report, REPORT_DIR / "audit_results.csv")
    save_to_html(report, REPORT_DIR / "audit_report.html")

    print("Audit complete.")
    print(f"Overall score: {overall_score}/100")
    print(f"Reports saved in: {REPORT_DIR.resolve()}")


if __name__ == "__main__":
    main()
