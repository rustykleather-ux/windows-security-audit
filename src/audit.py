import platform
import csv
from datetime import datetime

def get_system_info():
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "scan_time": datetime.now().isoformat()
    }

def save_to_csv(data, filename="audit_results.csv"):
    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=data.keys())
        writer.writeheader()
        writer.writerow(data)

def main():
    results = get_system_info()
    save_to_csv(results)
    print("Audit complete. Results saved to audit_results.csv")

if __name__ == "__main__":
    main()
