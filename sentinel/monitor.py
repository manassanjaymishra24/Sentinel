"""Live Sentinel monitor CLI."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from sentinel.audit import ReportGenerator
from sentinel.demo import analyze_events
from sentinel.windows_events import DEFAULT_LOGS, WindowsEventLogReader


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Monitor local Windows Event Logs with Sentinel.")
    parser.add_argument(
        "--source", choices=["windows"], default="windows", help="Live telemetry source."
    )
    parser.add_argument(
        "--logs", nargs="*", default=DEFAULT_LOGS, help="Windows Event Log names to read."
    )
    parser.add_argument(
        "--since-minutes", type=int, default=5, help="Lookback window per polling cycle."
    )
    parser.add_argument(
        "--max-events", type=int, default=50, help="Maximum events per log per polling cycle."
    )
    parser.add_argument("--interval", type=int, default=30, help="Seconds between polling cycles.")
    parser.add_argument("--once", action="store_true", help="Run one polling cycle and exit.")
    parser.add_argument(
        "--json-only", action="store_true", help="Print machine-readable reasoning JSON only."
    )
    parser.add_argument(
        "--no-response-plan", action="store_true", help="Do not print the dry-run response plan."
    )
    parser.add_argument(
        "--report-dir", type=Path, help="Optional directory to write markdown incident reports."
    )
    parser.add_argument(
        "--response-dir", type=Path, help="Optional directory to write response plan JSON files."
    )
    parser.add_argument(
        "--execute-response",
        action="store_true",
        help="Prepare non-dry-run response steps where supported.",
    )
    parser.add_argument(
        "--allow-execute",
        action="store_true",
        help="Required with --execute-response to leave dry-run mode.",
    )
    return parser


def run_cycle(args: argparse.Namespace) -> int:
    reader = WindowsEventLogReader(
        log_names=args.logs, since_minutes=args.since_minutes, max_events=args.max_events
    )
    events = reader.read_events()
    if reader.last_errors:
        print(json.dumps({"log_read_errors": reader.last_errors}, indent=2))
    if not events:
        print("No Windows events found in the requested window.")
        return 0

    output, record, response_plan, flags, output_flags, valid = analyze_events(
        events,
        response_dry_run=not args.execute_response,
        allow_execute=args.allow_execute,
    )
    print(json.dumps(output, indent=2))
    if flags or output_flags or not valid:
        print(json.dumps({"sanitization_flags": flags, "output_flags": output_flags}, indent=2))
    if not args.json_only:
        print()
        print(ReportGenerator().incident_markdown(record))
        if not args.no_response_plan:
            print()
            print(response_plan.markdown())
    write_outputs(args, record, response_plan)
    return len(events)


def write_outputs(args: argparse.Namespace, record, response_plan) -> None:
    if args.report_dir:
        args.report_dir.mkdir(parents=True, exist_ok=True)
        report_path = args.report_dir / f"{record.decision_id}.md"
        ReportGenerator().write_incident_report(record, report_path)
        print(f"\nWrote incident report to {report_path}")
    if args.response_dir:
        args.response_dir.mkdir(parents=True, exist_ok=True)
        response_path = args.response_dir / f"{record.decision_id}.json"
        response_path.write_text(json.dumps(response_plan.to_dict(), indent=2), encoding="utf-8")
        print(f"\nWrote response plan to {response_path}")


def main() -> None:
    args = build_arg_parser().parse_args()
    while True:
        run_cycle(args)
        if args.once:
            return
        time.sleep(max(1, args.interval))


if __name__ == "__main__":
    main()
