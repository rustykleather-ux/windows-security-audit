import platform
import csv
import subprocess
from datetime import datetime

 
def run_powershell(command):
    try:
        result = subprocess.run(
            ["powershell", "-Command", command], 
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
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
 return run_powershell(
      "Get-WinEvent -FilterHashTable @{LogName= 'Security'; Id=4625} -MaxEvents 10 |"
      "Select-Object TimeCreated, Provider Name, Id, Messge | ConvertTo-Json"
 )

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
 
    save_to_csv(results)

    print("Audit complete. Results saved to audit_results.csv")


if __name__ == "__main__":
    main()
