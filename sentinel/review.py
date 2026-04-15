"""Human approval CLI for Sentinel response plans."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.response import ResponseExecutor, ResponsePlan
from sentinel.storage import IncidentStore


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review, approve, and optionally execute a Sentinel response plan.")
    parser.add_argument("plan", type=Path, help="Path to a response plan JSON file.")
    parser.add_argument("--output", type=Path, help="Where to write the reviewed plan. Defaults to updating the input file.")
    parser.add_argument("--approve-all", action="store_true", help="Approve every human-gated step without prompting.")
    parser.add_argument("--reject-all", action="store_true", help="Reject every human-gated step without prompting.")
    parser.add_argument("--execute", action="store_true", help="Execute approved steps after review.")
    parser.add_argument("--allow-execute", action="store_true", help="Required with --execute to run local response commands.")
    parser.add_argument("--forensics-dir", type=Path, default=Path("sentinel_data/forensics"), help="Directory for approved forensics snapshots.")
    parser.add_argument("--incident-db", type=Path, help="Optional SQLite database path for recording the review outcome.")
    parser.add_argument("--actor", default="local-analyst", help="Reviewer name stored in the incident database.")
    parser.add_argument("--non-interactive", action="store_true", help="Do not prompt. Requires --approve-all or --reject-all.")
    return parser


def review_plan(plan: ResponsePlan, approve_all: bool = False, reject_all: bool = False, non_interactive: bool = False) -> ResponsePlan:
    if approve_all and reject_all:
        raise ValueError("--approve-all and --reject-all cannot be used together")
    if non_interactive and not (approve_all or reject_all):
        raise ValueError("--non-interactive requires --approve-all or --reject-all")

    for index, step in enumerate(plan.steps, start=1):
        if not step.requires_human:
            step.approved = True
            if step.status == "pending_approval":
                step.status = "approved"
            continue

        if approve_all:
            approved = True
        elif reject_all:
            approved = False
        else:
            approved = prompt_for_approval(index, step.action, step.target, step.command_preview)
        step.approved = approved
        step.status = "approved" if approved else "rejected"
    return plan


def prompt_for_approval(index: int, action: str, target: str | None, preview: str) -> bool:
    print(f"\nStep {index}: {action}")
    print(f"Target: {target}")
    print(f"Preview: {preview}")
    answer = input("Approve this step? Type 'approve' to approve: ").strip().lower()
    return answer == "approve"


def main() -> None:
    args = build_arg_parser().parse_args()
    plan = ResponsePlan.read_json(args.plan)
    reviewed = review_plan(
        plan,
        approve_all=args.approve_all,
        reject_all=args.reject_all,
        non_interactive=args.non_interactive,
    )
    output_path = args.output or args.plan
    reviewed.write_json(output_path)
    print(f"Wrote reviewed response plan to {output_path}")
    if args.incident_db:
        outcome = "approved" if any(step.approved for step in reviewed.steps) else "rejected"
        IncidentStore(args.incident_db).record_approval(reviewed.decision_id, outcome, actor=args.actor, details=reviewed.to_dict())
        print(f"Recorded review outcome in {args.incident_db}")

    if args.execute:
        results = ResponseExecutor(forensics_dir=args.forensics_dir).execute_plan(reviewed, allow_execute=args.allow_execute)
        print(json.dumps({"execution_results": [result.to_dict() for result in results]}, indent=2))


if __name__ == "__main__":
    main()
