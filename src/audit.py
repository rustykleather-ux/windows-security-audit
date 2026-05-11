import platform
import csv
import subprocess
from datetime import datetime


def summarize_firewall(firewall_status):
    if '"Enabled":  1' in firewall_status and firewall_status.count('"Enabled":  1') >= 3:
        return "PASS - All firewall profiles enabled"
    return "FAIL - One or more firewall profiles may be disabled"


def summarize_defender(defender_status):
    if '"RealTimeProtectionEnabled":  true' in defender_status:
        return "PASS - Defender real-time protection enabled"
    return "FAIL - Defender real-time protection may be disabled"


def summarize_bitlocker(bitlocker_status):
    if "Protection Status:    Protection On" in bitlocker_status:
        return "PASS - BitLocker protection enabled"
    if "Protection Status:    Protection Off" in bitlocker_status:
        return "FAIL - BitLocker protection is off"
    return "REVIEW - BitLocker status unclear"


def summarize_password_policy(password_policy):
    if "Minimum password length:" in password_policy and "Lockout threshold:" in password_policy:
        return "PASS - Password policy and lockout policy detected"
    return "REVIEW - Password policy could not be verified"


def summarize_failed_logins(failed_logins):
    if "Event ID: 4625" in failed_logins:
        return "REVIEW - Failed login events found"
    if "No failed login events found" in failed_logins:
        return "PASS - No failed login events found"
    return "REVIEW - Failed login status unclear"
 
def run_powershell(command):
    try:
        result = subprocess.run(
            ["powershell", "-Command", command], 
            capture_output=True,
            text=True
        )
        if result.stdout.strip():
            return result.stdout.strip()

        if result.stderr.strip():
            return "ERROR: " + result.stderr.strip()

        return "No output returned"

    except Exception as e:
        return f"Error: {e}"


def get_system_info():
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "scan_time": datetime.now().isoformat()
    }

def get_firewall_status():
    return run_powershell(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    )


def get_defender_status():
    return run_powershell(
        "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json"
    )


def get_local_admins():
    return run_powershell(
        "Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass | ConvertTo-Json"
    )

def get_bitlocker_status():
    return run_powershell(
       "manage-bde -status C:"
    )  

def get_password_policy():
    output = run_powershell("net accounts")

    # Clean line breaks for CSV readability
    output = output.replace("\n", " | ")

    return output

def get_failed_logins():
    output = run_powershell(
        'wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:5 /f:text'
    )

    if "No events were found" in output:
        return "No failed login events found"

    return output
def save_to_csv(data, filename="audit_results.csv"):
    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=data.keys())
        writer.writeheader()
        writer.writerow(data)
#  HTML Output
def save_to_html(data, filename="audit_report.html"):
    html = f"""
    <html>
    <head>
        <title>Windows Security Audit Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
            }}
            h1 {{
                color: #333;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
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
            <tr><th>Hostname</th><td>{data.get("hostname")}</td></tr>
            <tr><th>OS</th><td>{data.get("os")}</td></tr>
            <tr><th>OS Version</th><td>{data.get("os_version")}</td></tr>
            <tr><th>Architecture</th><td>{data.get("architecture")}</td></tr>
            <tr><th>Scan Time</th><td>{data.get("scan_time")}</td></tr>
        </table>

        <h2>Security Summary</h2>
        <table>
            <tr><th>Check</th><th>Result</th></tr>
            <tr><td>Firewall</td><td>{data.get("firewall_summary")}</td></tr>
            <tr><td>Defender</td><td>{data.get("defender_summary")}</td></tr>
            <tr><td>BitLocker</td><td>{data.get("bitlocker_summary")}</td></tr>
            <tr><td>Password Policy</td><td>{data.get("password_policy_summary")}</td></tr>
            <tr><td>Failed Logins</td><td>{data.get("failed_login_summary")}</td></tr>
        </table>

        <h2>Raw Audit Data</h2>

        <h3>Firewall Status</h3>
        <pre>{data.get("firewall_status")}</pre>

        <h3>Defender Status</h3>
        <pre>{data.get("defender_status")}</pre>

        <h3>Local Administrators</h3>
        <pre>{data.get("local_admins")}</pre>

        <h3>BitLocker Status</h3>
        <pre>{data.get("bitlocker_status")}</pre>

        <h3>Password Policy</h3>
        <pre>{data.get("password_policy")}</pre>

        <h3>Failed Login Events</h3>
        <pre>{data.get("failed_logins")}</pre>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as file:
        file.write(html)


def main():
    results = get_system_info()

    results["firewall_status"] = get_firewall_status()
    results["defender_status"] = get_defender_status()
    results["local_admins"] = get_local_admins()
    results["bitlocker_status"] = get_bitlocker_status()
    results["password_policy"] = get_password_policy()
    results["failed_logins"] = get_failed_logins()

    results["firewall_summary"] = summarize_firewall(results["firewall_status"])
    results["defender_summary"] = summarize_defender(results["defender_status"])
    results["bitlocker_summary"] = summarize_bitlocker(results["bitlocker_status"])
    results["password_policy_summary"] = summarize_password_policy(results["password_policy"])
    results["failed_login_summary"] = summarize_failed_logins(results["failed_logins"])
  
    save_to_csv(results)
    save_to_html(results)
    print("Audit complete. Results saved to audit_results.csv and audit_report.html")


if __name__ == "__main__":
    main()
