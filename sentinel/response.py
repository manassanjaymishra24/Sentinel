"""Layer 5 local response planning and dry-run execution."""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from sentinel.events import UnifiedSecurityEvent


def powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@dataclass(slots=True)
class ResponseStep:
    action: str
    target: str | None
    command_preview: str
    command_args: list[str] = field(default_factory=list)
    rollback_preview: str | None = None
    dry_run: bool = True
    requires_human: bool = True
    reversible: bool = True
    approved: bool = False
    status: str = "planned"
    rationale: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        return data


@dataclass(slots=True)
class ResponsePlan:
    decision_id: str
    dry_run: bool
    steps: list[ResponseStep]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "dry_run": self.dry_run,
            "steps": [step.to_dict() for step in self.steps],
            "warnings": self.warnings,
        }

    def markdown(self) -> str:
        lines = [
            "## Local Response Plan",
            "",
            f"- Decision ID: `{self.decision_id}`",
            f"- Dry Run: `{self.dry_run}`",
        ]
        if self.warnings:
            lines.extend(["", "### Warnings", ""])
            lines.extend(f"- {warning}" for warning in self.warnings)
        lines.extend(["", "### Steps", ""])
        if not self.steps:
            lines.append("- No response steps planned.")
        for step in self.steps:
            lines.append(
                f"- `{step.action}` target=`{step.target}` status=`{step.status}` "
                f"human_required=`{step.requires_human}` approved=`{step.approved}` reversible=`{step.reversible}`"
            )
            lines.append(f"  Command preview: `{step.command_preview}`")
            if step.rollback_preview:
                lines.append(f"  Rollback preview: `{step.rollback_preview}`")
            if step.rationale:
                lines.append(f"  Rationale: {step.rationale}")
        return "\n".join(lines)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResponsePlan:
        return cls(
            decision_id=str(data["decision_id"]),
            dry_run=bool(data.get("dry_run", True)),
            steps=[response_step_from_dict(step) for step in data.get("steps", [])],
            warnings=list(data.get("warnings", [])),
        )

    @classmethod
    def read_json(cls, path: str | Path) -> ResponsePlan:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def write_json(self, path: str | Path) -> Path:
        output = Path(path)
        output.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return output


def response_step_from_dict(data: dict[str, Any]) -> ResponseStep:
    created_at = data.get("created_at")
    parsed_created_at = (
        datetime.fromisoformat(created_at) if created_at else datetime.now(timezone.utc)
    )
    return ResponseStep(
        action=str(data.get("action", "unknown")),
        target=data.get("target"),
        command_preview=str(data.get("command_preview", "")),
        command_args=list(data.get("command_args", [])),
        rollback_preview=data.get("rollback_preview"),
        dry_run=bool(data.get("dry_run", True)),
        requires_human=bool(data.get("requires_human", True)),
        reversible=bool(data.get("reversible", True)),
        approved=bool(data.get("approved", False)),
        status=str(data.get("status", "planned")),
        rationale=str(data.get("rationale", "")),
        created_at=parsed_created_at,
    )


class WindowsFirewallAdapter:
    rule_prefix = "SENTINEL Block"

    def build_block_step(
        self,
        remote_address: str,
        dry_run: bool,
        requires_human: bool,
        rationale: str,
    ) -> ResponseStep:
        rule_name = self.rule_name(remote_address)
        return ResponseStep(
            action="block_ip_windows_firewall",
            target=remote_address,
            command_preview=f"Would add Windows Firewall outbound block rule '{rule_name}' for {remote_address}.",
            command_args=self.block_command(remote_address),
            rollback_preview=self.unblock_preview(remote_address),
            dry_run=dry_run,
            requires_human=requires_human,
            reversible=True,
            approved=not requires_human,
            status="dry_run" if dry_run else "pending_approval",
            rationale=rationale,
        )

    def rule_name(self, remote_address: str) -> str:
        safe_address = remote_address.replace(":", "-").replace("/", "_")
        return f"{self.rule_prefix} {safe_address}"

    def block_command(self, remote_address: str) -> list[str]:
        rule_name = self.rule_name(remote_address)
        script = (
            f"New-NetFirewallRule -DisplayName '{rule_name}' "
            f"-Direction Outbound -Action Block -RemoteAddress '{remote_address}'"
        )
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]

    def unblock_preview(self, remote_address: str) -> str:
        return f"Remove-NetFirewallRule -DisplayName '{self.rule_name(remote_address)}'"


class WindowsProcessAdapter:
    def build_kill_step(
        self,
        process_id: str,
        process_name: str | None,
        dry_run: bool,
        requires_human: bool,
        rationale: str,
    ) -> ResponseStep:
        target = f"{process_name or 'process'} pid={process_id}"
        return ResponseStep(
            action="kill_process_windows",
            target=target,
            command_preview=f"Would stop process {target}.",
            command_args=self.kill_command(process_id),
            rollback_preview=None,
            dry_run=dry_run,
            requires_human=requires_human,
            reversible=False,
            approved=not requires_human,
            status="dry_run" if dry_run else "pending_approval",
            rationale=rationale,
        )

    def kill_command(self, process_id: str) -> list[str]:
        script = f"Stop-Process -Id {int(process_id)} -Force"
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]


class WindowsQuarantineAdapter:
    def __init__(self, quarantine_dir: str | Path = "sentinel_data/quarantine") -> None:
        self.quarantine_dir = Path(quarantine_dir)

    def build_quarantine_step(
        self,
        file_path: str,
        dry_run: bool,
        requires_human: bool,
        rationale: str,
    ) -> ResponseStep:
        source = Path(file_path)
        destination = self.quarantine_dir / source.name
        return ResponseStep(
            action="quarantine_file_windows",
            target=file_path,
            command_preview=f"Would move file {file_path} to quarantine path {destination}.",
            command_args=self.quarantine_command(file_path, destination),
            rollback_preview=f"Move-Item -LiteralPath {powershell_quote(str(destination))} -Destination {powershell_quote(file_path)} -Force",
            dry_run=dry_run,
            requires_human=requires_human,
            reversible=True,
            approved=not requires_human,
            status="dry_run" if dry_run else "pending_approval",
            rationale=rationale,
        )

    def quarantine_command(self, file_path: str, destination: Path) -> list[str]:
        script = (
            f"New-Item -ItemType Directory -Force -Path {powershell_quote(str(destination.parent))} | Out-Null; "
            f"Move-Item -LiteralPath {powershell_quote(file_path)} -Destination {powershell_quote(str(destination))} -Force"
        )
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]


class ForensicsCollector:
    def __init__(self, output_dir: str | Path = "sentinel_data/forensics") -> None:
        self.output_dir = Path(output_dir)

    def collect(self, decision_id: str, step: ResponseStep) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        safe_target = self._safe_name(step.target or "unknown")
        output = (
            self.output_dir
            / f"{decision_id}_{safe_target}_{int(datetime.now(timezone.utc).timestamp())}.json"
        )
        snapshot = {
            "decision_id": decision_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target": step.target,
            "action": step.action,
            "rationale": step.rationale,
            "note": "Local non-destructive forensics snapshot placeholder. Integrate richer collectors as permissions allow.",
        }
        output.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        return output

    def _safe_name(self, value: str) -> str:
        safe = "".join(char if char.isalnum() else "_" for char in value)
        return safe[:80] or "unknown"


@dataclass(slots=True)
class ExecutionResult:
    action: str
    target: str | None
    status: str
    message: str
    returncode: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ResponseExecutor:
    executable_actions = {
        "block_ip_windows_firewall",
        "kill_process_windows",
        "preserve_forensics",
        "quarantine_file_windows",
    }

    def __init__(self, forensics_dir: str | Path = "sentinel_data/forensics") -> None:
        self.forensics = ForensicsCollector(forensics_dir)

    def execute_plan(
        self, plan: ResponsePlan, allow_execute: bool = False
    ) -> list[ExecutionResult]:
        return [
            self.execute_step(step, decision_id=plan.decision_id, allow_execute=allow_execute)
            for step in plan.steps
        ]

    def execute_step(
        self, step: ResponseStep, decision_id: str = "manual", allow_execute: bool = False
    ) -> ExecutionResult:
        if step.action not in self.executable_actions:
            step.status = "skipped"
            return ExecutionResult(
                step.action, step.target, "skipped", "No local executor for this action."
            )
        if step.requires_human and not step.approved:
            step.status = "blocked"
            return ExecutionResult(
                step.action, step.target, "blocked", "Human approval is required before execution."
            )
        if step.dry_run or not allow_execute:
            step.status = "dry_run"
            return ExecutionResult(step.action, step.target, "dry_run", step.command_preview)
        if step.action == "preserve_forensics":
            output = self.forensics.collect(decision_id, step)
            step.status = "executed"
            return ExecutionResult(
                step.action, step.target, "executed", f"Wrote forensics snapshot to {output}"
            )
        if not step.command_args:
            step.status = "failed"
            return ExecutionResult(
                step.action, step.target, "failed", "No command_args were provided."
            )

        completed = subprocess.run(step.command_args, capture_output=True, text=True, check=False)
        step.status = "executed" if completed.returncode == 0 else "failed"
        message = completed.stdout.strip() or completed.stderr.strip() or step.status
        return ExecutionResult(step.action, step.target, step.status, message, completed.returncode)


class LocalResponsePlanner:
    """Converts reasoning recommendations into local response steps.

    This planner intentionally defaults to dry-run. It prepares auditable steps that
    can later be wired to real system integrations behind explicit approval gates.
    """

    def __init__(self) -> None:
        self.firewall = WindowsFirewallAdapter()
        self.processes = WindowsProcessAdapter()
        self.quarantine = WindowsQuarantineAdapter()

    def build_plan(
        self,
        decision_id: str,
        recommended_actions: list[dict[str, Any]],
        events: list[UnifiedSecurityEvent],
        dry_run: bool = True,
        allow_execute: bool = False,
    ) -> ResponsePlan:
        warnings: list[str] = []
        effective_dry_run = dry_run or not allow_execute
        if not dry_run and not allow_execute:
            warnings.append("Execution requested without allow_execute; forcing dry-run mode.")

        steps: list[ResponseStep] = []
        for recommendation in recommended_actions:
            action = recommendation.get("action", "monitor")
            rationale = str(recommendation.get("rationale") or "")
            requires_human = bool(recommendation.get("requires_human", True))
            steps.extend(
                self._steps_for_action(action, rationale, requires_human, events, effective_dry_run)
            )

        return ResponsePlan(
            decision_id=decision_id, dry_run=effective_dry_run, steps=steps, warnings=warnings
        )

    def _steps_for_action(
        self,
        action: str,
        rationale: str,
        requires_human: bool,
        events: list[UnifiedSecurityEvent],
        dry_run: bool,
    ) -> list[ResponseStep]:
        if action == "monitor":
            return [
                ResponseStep(
                    action="monitor",
                    target=None,
                    command_preview="No local command. Continue collecting telemetry.",
                    dry_run=dry_run,
                    requires_human=False,
                    reversible=True,
                    status="dry_run" if dry_run else "recorded",
                    rationale=rationale,
                )
            ]
        if action == "alert_analyst":
            return [
                ResponseStep(
                    action="alert_analyst",
                    target=None,
                    command_preview="No local command. Queue decision for analyst review.",
                    dry_run=dry_run,
                    requires_human=True,
                    reversible=True,
                    status="dry_run" if dry_run else "recorded",
                    rationale=rationale,
                )
            ]
        if action == "preserve_forensics":
            return self._preserve_forensics_steps(events, rationale, dry_run)
        if action == "isolate_candidate_host":
            return self._isolate_host_steps(events, rationale, dry_run, requires_human=True)
        if action == "kill_suspicious_process":
            return self._kill_process_steps(events, rationale, dry_run, requires_human=True)
        if action == "quarantine_suspicious_file":
            return self._quarantine_file_steps(events, rationale, dry_run, requires_human=True)
        return [
            ResponseStep(
                action=f"unsupported:{action}",
                target=None,
                command_preview="No command generated for unsupported action.",
                dry_run=True,
                requires_human=True,
                reversible=True,
                status="skipped",
                rationale=rationale,
            )
        ]

    def _preserve_forensics_steps(
        self,
        events: list[UnifiedSecurityEvent],
        rationale: str,
        dry_run: bool,
    ) -> list[ResponseStep]:
        targets = sorted({event.entity_name or event.entity_id or "unknown" for event in events})
        return [
            ResponseStep(
                action="preserve_forensics",
                target=target,
                command_preview=f"Collect process, network, and event-log snapshot for {target}.",
                dry_run=dry_run,
                requires_human=False,
                reversible=True,
                status="dry_run" if dry_run else "recorded",
                rationale=rationale,
            )
            for target in targets
        ]

    def _isolate_host_steps(
        self,
        events: list[UnifiedSecurityEvent],
        rationale: str,
        dry_run: bool,
        requires_human: bool,
    ) -> list[ResponseStep]:
        targets = sorted(
            {
                event.target_entity
                for event in events
                if event.target_entity and self._is_ip(event.target_entity)
            }
        )
        if not targets:
            targets = ["candidate_host"]
        steps = []
        for target in targets:
            if self._is_ip(target):
                steps.append(
                    self.firewall.build_block_step(target, dry_run, requires_human, rationale)
                )
            else:
                steps.append(
                    ResponseStep(
                        action="isolate_candidate_host",
                        target=target,
                        command_preview=self._isolation_preview(target),
                        dry_run=dry_run,
                        requires_human=requires_human,
                        reversible=True,
                        status="dry_run" if dry_run else "requires_integration",
                        rationale=rationale,
                    )
                )
        return steps

    def _kill_process_steps(
        self,
        events: list[UnifiedSecurityEvent],
        rationale: str,
        dry_run: bool,
        requires_human: bool,
    ) -> list[ResponseStep]:
        process_targets = sorted(
            {
                (str(event.raw_data.get("ProcessId")), event.entity_name)
                for event in events
                if event.raw_data.get("ProcessId")
                and str(event.raw_data.get("ProcessId")).isdigit()
            }
        )
        return [
            self.processes.build_kill_step(
                process_id, process_name, dry_run, requires_human, rationale
            )
            for process_id, process_name in process_targets
        ] or [
            ResponseStep(
                action="kill_process_windows",
                target=None,
                command_preview="No process ID available; cannot prepare Stop-Process command.",
                dry_run=True,
                requires_human=True,
                reversible=False,
                status="skipped",
                rationale=rationale,
            )
        ]

    def _quarantine_file_steps(
        self,
        events: list[UnifiedSecurityEvent],
        rationale: str,
        dry_run: bool,
        requires_human: bool,
    ) -> list[ResponseStep]:
        file_targets = sorted(
            {
                str(event.raw_data.get("TargetFilename") or event.target_entity)
                for event in events
                if event.raw_data.get("TargetFilename")
                or (event.entity_type == "file" and event.target_entity)
            }
        )
        return [
            self.quarantine.build_quarantine_step(file_path, dry_run, requires_human, rationale)
            for file_path in file_targets
        ] or [
            ResponseStep(
                action="quarantine_file_windows",
                target=None,
                command_preview="No file path available; cannot prepare quarantine command.",
                dry_run=True,
                requires_human=True,
                reversible=True,
                status="skipped",
                rationale=rationale,
            )
        ]

    def _isolation_preview(self, target: str) -> str:
        if self._is_ip(target):
            return f"Would add Windows Firewall block rule for remote address {target}."
        return f"Would isolate host or endpoint entity {target} via EDR/firewall integration."

    def _is_ip(self, value: str) -> bool:
        try:
            ip_address(value)
        except ValueError:
            return False
        return True
