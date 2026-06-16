import argparse
import base64
import csv
import html
import json
import subprocess
from datetime import datetime
from pathlib import Path

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
if not Path(POWERSHELL).exists():
    POWERSHELL = "powershell"


def parse_args():
    parser = argparse.ArgumentParser(description="Windows Security Assessor Fleet Runner")
    parser.add_argument("--script", required=True, help="Path to windows_security_assessor.py")
    parser.add_argument("--fleet", required=True, help="Text file with one computer name per line")
    parser.add_argument("--output", default="fleet_output", help="Output directory")
    parser.add_argument("--timeout", type=int, default=900, help="Timeout per remote computer in seconds")
    parser.add_argument("--summary", action="store_true", help="Print fleet summary")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    parser.add_argument("--no-cleanup", action="store_true", help="Leave temporary files on remote computers")
    return parser.parse_args()


def read_computers(path):
    computers = []
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            value = line.strip()
            if value and not value.startswith("#"):
                computers.append(value)
    return computers


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


def run_remote_scan(computer, script_text, timeout=900, cleanup=True):
    encoded_script = base64.b64encode(script_text.encode("utf-8")).decode("ascii")
    cleanup_value = "$true" if cleanup else "$false"

    ps_command = f'''
$ErrorActionPreference = 'Stop'
$encoded = '{encoded_script}'
$cleanup = {cleanup_value}

Invoke-Command -ComputerName '{computer}' -ScriptBlock {{
    param($encodedScript, $cleanupRemote)

    $remoteDir = Join-Path $env:TEMP 'WindowsSecurityAssessorFleet'
    $scriptPath = Join-Path $remoteDir 'windows_security_assessor_remote.py'
    $outputDir = Join-Path $remoteDir 'audit_output'

    New-Item -ItemType Directory -Path $remoteDir -Force | Out-Null

    $scriptBytes = [Convert]::FromBase64String($encodedScript)
    [System.IO.File]::WriteAllBytes($scriptPath, $scriptBytes)

    $python = (Get-Command python -ErrorAction SilentlyContinue).Source
    $usePyLauncher = $false

    if (-not $python) {{
        $python = (Get-Command py -ErrorAction SilentlyContinue).Source
        $usePyLauncher = $true
    }}

    if (-not $python) {{
        throw 'Python was not found on the remote computer.'
    }}

    if (Test-Path $outputDir) {{
        Remove-Item -Path $outputDir -Recurse -Force -ErrorAction SilentlyContinue
    }}

    if ($usePyLauncher) {{
        & $python -3 $scriptPath --json --quiet --output $outputDir | Out-Null
    }} else {{
        & $python $scriptPath --json --quiet --output $outputDir | Out-Null
    }}

    $jsonPath = Join-Path $outputDir 'audit_report.json'

    if (-not (Test-Path $jsonPath)) {{
        throw 'Remote audit did not produce audit_report.json.'
    }}

    $json = Get-Content -Path $jsonPath -Raw

    if ($cleanupRemote) {{
        Remove-Item -Path $remoteDir -Recurse -Force -ErrorAction SilentlyContinue
    }}

    return $json
}} -ArgumentList $encoded, $cleanup
'''

    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode != 0:
        raise RuntimeError(stderr or stdout or f"Remote scan failed with code {result.returncode}")

    if not stdout:
        raise RuntimeError("Remote scan returned no JSON output")

    return json.loads(stdout)


def build_summary(results):
    summary = {
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "total_computers": len(results),
        "successful_scans": 0,
        "failed_scans": 0,
        "average_score": 0,
        "grade_counts": {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0},
        "status_counts": {"PASS": 0, "REVIEW": 0, "FAIL": 0},
        "high_risk_findings": 0,
    }

    scores = []

    for item in results:
        if item.get("status") != "SUCCESS":
            summary["failed_scans"] += 1
            continue

        report = item.get("report", {})
        summary["successful_scans"] += 1

        score = int(report.get("overall_score", 0))
        grade = report.get("overall_grade", get_letter_grade(score))
        scores.append(score)
        summary["grade_counts"][grade] = summary["grade_counts"].get(grade, 0) + 1

        for check in report.get("checks", {}).values():
            check_summary = check.get("summary", {})
            status = check_summary.get("status", "REVIEW")
            risk = check_summary.get("remediation", {}).get("risk", "Informational")
            summary["status_counts"][status] = summary["status_counts"].get(status, 0) + 1

            if risk == "High" and status in ["FAIL", "REVIEW"]:
                summary["high_risk_findings"] += 1

    if scores:
        summary["average_score"] = round(sum(scores) / len(scores))

    return summary


def save_json(results, summary, path):
    with open(path, "w", encoding="utf-8") as file:
        json.dump({"summary": summary, "results": results}, file, indent=4)


def save_csv(results, path):
    rows = []

    for item in results:
        computer = item.get("computer", "")

        if item.get("status") != "SUCCESS":
            rows.append({
                "computer": computer,
                "scan_status": "FAILED",
                "overall_score": "",
                "overall_grade": "",
                "fail_count": "",
                "review_count": "",
                "high_risk_count": "",
                "top_findings": "",
                "error": item.get("error", ""),
            })
            continue

        report = item.get("report", {})
        fail_count = 0
        review_count = 0
        high_risk_count = 0
        top_findings = []

        for check_name, check in report.get("checks", {}).items():
            summary = check.get("summary", {})
            status = summary.get("status", "REVIEW")
            risk = summary.get("remediation", {}).get("risk", "Informational")
            message = summary.get("message", "")

            if status == "FAIL":
                fail_count += 1
                top_findings.append(f"{check_name}: {message}")
            if status == "REVIEW":
                review_count += 1
            if risk == "High" and status in ["FAIL", "REVIEW"]:
                high_risk_count += 1

        rows.append({
            "computer": computer,
            "scan_status": "SUCCESS",
            "overall_score": report.get("overall_score", ""),
            "overall_grade": report.get("overall_grade", ""),
            "fail_count": fail_count,
            "review_count": review_count,
            "high_risk_count": high_risk_count,
            "top_findings": "; ".join(top_findings[:10]),
            "error": "",
        })

    fieldnames = [
        "computer", "scan_status", "overall_score", "overall_grade",
        "fail_count", "review_count", "high_risk_count", "top_findings", "error",
    ]

    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def save_dashboard(results, summary, path):
    grade_cards = ""
    for grade in ["A", "B", "C", "D", "F"]:
        grade_cards += f'''
        <div class="metric">
            <div class="label">Grade {grade}</div>
            <div class="value grade-{grade.lower()}">{summary["grade_counts"].get(grade, 0)}</div>
        </div>
        '''

    machine_rows = ""

    for item in sorted(results, key=lambda x: x.get("computer", "")):
        computer = html.escape(str(item.get("computer", "")))

        if item.get("status") != "SUCCESS":
            machine_rows += f'''
            <tr>
                <td class="machine">{computer}</td>
                <td><span class="badge fail">FAILED</span></td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>{html.escape(str(item.get("error", "")))}</td>
            </tr>
            '''
            continue

        report = item.get("report", {})
        score = int(report.get("overall_score", 0))
        grade = report.get("overall_grade", get_letter_grade(score))
        fail_count = 0
        review_count = 0
        high_risk_count = 0
        top_findings = []

        for check_name, check in report.get("checks", {}).items():
            check_summary = check.get("summary", {})
            status = check_summary.get("status", "REVIEW")
            risk = check_summary.get("remediation", {}).get("risk", "Informational")
            message = check_summary.get("message", "")

            if status == "FAIL":
                fail_count += 1
                top_findings.append(f"{check_name}: {message}")
            if status == "REVIEW":
                review_count += 1
            if risk == "High" and status in ["FAIL", "REVIEW"]:
                high_risk_count += 1

        top_text = "; ".join(top_findings[:5]) if top_findings else "No failed checks"

        machine_rows += f'''
        <tr>
            <td class="machine">{computer}</td>
            <td><span class="badge pass">SUCCESS</span></td>
            <td class="grade-{grade.lower()}"><strong>{html.escape(str(grade))}</strong></td>
            <td>{score}/100</td>
            <td>{fail_count}</td>
            <td>{review_count}</td>
            <td>{high_risk_count}</td>
            <td>{html.escape(top_text)}</td>
        </tr>
        '''

    dashboard = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Windows Security Assessor Fleet Dashboard</title>
    <style>
        :root {{
            --bg: #f5f7fb;
            --card: #ffffff;
            --text: #1f2937;
            --muted: #6b7280;
            --border: #d8dee9;
            --pass: #15803d;
            --fail: #b91c1c;
        }}
        * {{ box-sizing: border-box; }}
        body {{ margin: 0; background: var(--bg); color: var(--text); font-family: Arial, Helvetica, sans-serif; line-height: 1.45; }}
        header {{ background: #111827; color: white; padding: 28px 40px; }}
        header h1 {{ margin: 0 0 8px 0; }}
        header p {{ margin: 0; color: #d1d5db; }}
        main {{ padding: 28px 40px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 16px; margin-bottom: 20px; }}
        .metric, .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08); }}
        .card {{ margin-bottom: 20px; }}
        .label {{ color: var(--muted); font-size: 13px; text-transform: uppercase; letter-spacing: 0.04em; font-weight: bold; }}
        .value {{ font-size: 34px; font-weight: bold; margin-top: 6px; }}
        .table-wrap {{ overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; min-width: 1100px; }}
        th, td {{ border-bottom: 1px solid var(--border); padding: 10px; text-align: left; vertical-align: top; }}
        th {{ background: #f3f4f6; font-size: 13px; text-transform: uppercase; color: #374151; }}
        .badge {{ display: inline-block; min-width: 78px; text-align: center; border-radius: 999px; padding: 4px 9px; color: white; font-weight: bold; font-size: 12px; }}
        .badge.pass {{ background: var(--pass); }}
        .badge.fail {{ background: var(--fail); }}
        .machine {{ font-weight: bold; }}
        .grade-a {{ color: #15803d; }}
        .grade-b {{ color: #16a34a; }}
        .grade-c {{ color: #ca8a04; }}
        .grade-d {{ color: #b45309; }}
        .grade-f {{ color: #b91c1c; }}
        footer {{ color: var(--muted); font-size: 12px; padding: 0 40px 28px 40px; }}
    </style>
</head>
<body>
    <header>
        <h1>Windows Security Assessor Fleet Dashboard</h1>
        <p>Generated: {html.escape(str(summary.get("scan_time", "")))}</p>
    </header>

    <main>
        <div class="grid">
            <div class="metric"><div class="label">Total Computers</div><div class="value">{summary.get("total_computers", 0)}</div></div>
            <div class="metric"><div class="label">Successful Scans</div><div class="value">{summary.get("successful_scans", 0)}</div></div>
            <div class="metric"><div class="label">Failed Scans</div><div class="value">{summary.get("failed_scans", 0)}</div></div>
            <div class="metric"><div class="label">Average Score</div><div class="value">{summary.get("average_score", 0)}/100</div></div>
            <div class="metric"><div class="label">High Risk Findings</div><div class="value">{summary.get("high_risk_findings", 0)}</div></div>
        </div>

        <div class="grid">
            {grade_cards}
        </div>

        <section class="card">
            <h2>Organization-Wide Results</h2>
            <div class="table-wrap">
                <table>
                    <tr>
                        <th>Computer</th>
                        <th>Scan Status</th>
                        <th>Grade</th>
                        <th>Score</th>
                        <th>Fail</th>
                        <th>Review</th>
                        <th>High Risk</th>
                        <th>Top Findings / Error</th>
                    </tr>
                    {machine_rows}
                </table>
            </div>
        </section>
    </main>

    <footer>Generated by Windows Security Assessor Fleet Runner. Validate findings before making production changes.</footer>
</body>
</html>
'''

    with open(path, "w", encoding="utf-8") as file:
        file.write(dashboard)


def main():
    args = parse_args()
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    script_path = Path(args.script)
    if not script_path.exists():
        raise FileNotFoundError(f"Audit script not found: {args.script}")

    computers = read_computers(args.fleet)
    script_text = script_path.read_text(encoding="utf-8")
    results = []

    for computer in computers:
        if not args.quiet:
            print(f"Running remote scan: {computer}")

        try:
            report = run_remote_scan(
                computer,
                script_text,
                timeout=args.timeout,
                cleanup=not args.no_cleanup,
            )
            results.append({"computer": computer, "status": "SUCCESS", "report": report})
        except Exception as exc:
            results.append({"computer": computer, "status": "FAILED", "error": str(exc)})

    summary = build_summary(results)

    save_json(results, summary, output_dir / "fleet_results.json")
    save_csv(results, output_dir / "fleet_results.csv")
    save_dashboard(results, summary, output_dir / "fleet_dashboard.html")

    if args.summary:
        print("\nFleet Summary")
        print("=" * 60)
        print(f"Total Computers: {summary['total_computers']}")
        print(f"Successful Scans: {summary['successful_scans']}")
        print(f"Failed Scans: {summary['failed_scans']}")
        print(f"Average Score: {summary['average_score']}/100")
        print(f"High Risk Findings: {summary['high_risk_findings']}")
        for grade in ["A", "B", "C", "D", "F"]:
            print(f"Grade {grade}: {summary['grade_counts'].get(grade, 0)}")

    if not args.quiet:
        print("Fleet audit complete.")
        print(f"Dashboard: {(output_dir / 'fleet_dashboard.html').resolve()}")
        print(f"CSV: {(output_dir / 'fleet_results.csv').resolve()}")
        print(f"JSON: {(output_dir / 'fleet_results.json').resolve()}")


if __name__ == "__main__":
    main()
