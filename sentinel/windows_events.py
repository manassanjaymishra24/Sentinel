"""Live Windows Event Log ingestion."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from typing import Any

from sentinel.events import SysmonParser, UnifiedSecurityEvent, WindowsEventLogParser
from sentinel.sysmon import SysmonSuspicionScorer

DEFAULT_LOGS = [
    "Security",
    "System",
    "Windows PowerShell",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
]


def quote_powershell_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class WindowsEventLogReader:
    """Reads recent Windows Event Log entries through PowerShell Get-WinEvent."""

    def __init__(
        self,
        log_names: list[str] | None = None,
        since_minutes: int = 5,
        max_events: int = 50,
        powershell_exe: str = "powershell",
    ) -> None:
        self.log_names = log_names or DEFAULT_LOGS
        self.since_minutes = since_minutes
        self.max_events = max_events
        self.powershell_exe = powershell_exe
        self.last_errors: list[str] = []
        self.parser = WindowsEventLogParser()
        self.sysmon_parser = SysmonParser()
        self.sysmon_scorer = SysmonSuspicionScorer()

    def build_command(self) -> list[str]:
        logs = ", ".join(quote_powershell_string(log_name) for log_name in self.log_names)
        script = f"""
$ErrorActionPreference = 'Continue'
$start = (Get-Date).AddMinutes(-{int(self.since_minutes)})
$logs = @({logs})
$items = foreach ($log in $logs) {{
  try {{
    Get-WinEvent -FilterHashtable @{{LogName=$log; StartTime=$start}} -MaxEvents {int(self.max_events)} |
      Select-Object @{{Name='LogName';Expression={{$log}}}}, ProviderName, Id, RecordId, TimeCreated, MachineName, LevelDisplayName, Message
  }} catch {{
    [pscustomobject]@{{LogName=$log; Error=$_.Exception.Message}}
  }}
}}
$items | ConvertTo-Json -Depth 6
""".strip()
        return [
            self.powershell_exe,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]

    def fetch_raw_events(self) -> list[dict[str, Any]]:
        completed = subprocess.run(  # noqa: S603
            self.build_command(),
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0 and not completed.stdout.strip():
            raise RuntimeError(
                completed.stderr.strip()
                or f"Get-WinEvent failed with exit code {completed.returncode}"
            )
        return self._parse_json_output(completed.stdout)

    def read_events(self) -> list[UnifiedSecurityEvent]:
        raw_events = self.fetch_raw_events()
        events = []
        for raw in raw_events:
            if raw.get("Error"):
                self.last_errors.append(f"{raw.get('LogName')}: {raw.get('Error')}")
                continue
            event = self._parse_event(raw)
            event.notes.append(f"live_log:{raw.get('LogName', 'unknown')}")
            event.anomaly_score = max(event.anomaly_score or 0.0, self._initial_anomaly_score(raw))
            events.append(event)
        return events

    def _parse_event(self, raw: dict[str, Any]) -> UnifiedSecurityEvent:
        log_name = str(raw.get("LogName") or "")
        if "Sysmon" in log_name:
            event = self.sysmon_parser.parse(self._expand_sysmon_message(raw))
            return self.sysmon_scorer.enrich(event)
        return self.parser.parse(raw)

    def _expand_sysmon_message(self, raw: dict[str, Any]) -> dict[str, Any]:
        expanded = dict(raw)
        message = str(raw.get("Message") or "")
        for line in message.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key and key not in expanded:
                expanded[key] = value
        if "EventID" not in expanded and "Id" in expanded:
            expanded["EventID"] = expanded["Id"]
        return expanded

    def _parse_json_output(self, output: str) -> list[dict[str, Any]]:
        text = output.strip()
        self.last_errors = []
        if not text:
            return []
        data = json.loads(text)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        raise ValueError(f"unexpected Get-WinEvent JSON root: {type(data).__name__}")

    def _initial_anomaly_score(self, raw: dict[str, Any]) -> float:
        if "Sysmon" in str(raw.get("LogName") or ""):
            return 0.0
        message = str(raw.get("Message") or "").lower()
        event_id = str(raw.get("Id") or "")
        if any(
            keyword in message
            for keyword in (
                "powershell",
                "encodedcommand",
                "mimikatz",
                "credential",
                "whoami",
                "net user",
            )
        ):
            return 0.75
        if event_id in {"4688", "4104", "4625", "7045"}:
            return 0.65
        return 0.45


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
