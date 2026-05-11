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

    save_to_csv(results)

    print("Audit complete. Results saved to audit_results.csv")


if __name__ == "__main__":
    main()
