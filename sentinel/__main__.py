"""Community Defender — run a security sweep.

Usage:
  python -m sentinel                    # Full scan, print report
  python -m sentinel --json             # Output as JSON
  python -m sentinel --json -o scan.json  # Save to file
  python -m sentinel --discord URL      # Alert to Discord webhook
  python -m sentinel --checks persistence,processes  # Specific checks only
  python -m sentinel --cron             # Quiet mode — only output if findings
"""
import argparse
import sys

from .scanner import SentinelScanner
from .alerts import AlertBus, StdoutAlert, FileAlert, DiscordWebhookAlert


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Community Defender — security sweep for the rest of us",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-o", "--output", default="", help="Save results to file")
    parser.add_argument("--discord", default="", help="Discord webhook URL for alerts")
    parser.add_argument("--log", default="", help="Append alerts to log file")
    parser.add_argument("--checks", default="", help="Comma-separated list of checks to run")
    parser.add_argument("--cron", action="store_true", help="Quiet mode — only output if findings")
    args = parser.parse_args()

    checks = args.checks.split(",") if args.checks else None
    scanner = SentinelScanner(checks=checks)

    result = scanner.scan()

    # Build alert bus
    transports = []
    if not args.cron or result.findings:
        transports.append(StdoutAlert())
    if args.log:
        transports.append(FileAlert(args.log))
    if args.discord:
        transports.append(DiscordWebhookAlert(args.discord))

    bus = AlertBus(transports)

    if args.json:
        output = scanner.scan_to_json(args.output)
        if not args.cron or result.findings:
            print(output)
    else:
        if not args.cron or result.findings:
            print(result.human_report())

    # Send alerts for findings
    if result.findings:
        bus.alert_findings(result)

    sys.exit(1 if result.critical_count > 0 else 0)


if __name__ == "__main__":
    main()
