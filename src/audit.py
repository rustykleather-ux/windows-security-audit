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

    print("Audit complete. Results saved to audit_results.csv")


if __name__ == "__main__":
    main()
