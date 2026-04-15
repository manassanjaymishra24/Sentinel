"""Sysmon enrichment and suspicion scoring."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.events import UnifiedSecurityEvent


SYSMON_EVENT_NAMES = {
    "1": "Process Create",
    "3": "Network Connection",
    "7": "Image Loaded",
    "10": "Process Access",
    "11": "File Create",
    "13": "Registry Value Set",
    "22": "DNS Query",
}


@dataclass(frozen=True, slots=True)
class SysmonFinding:
    rule_id: str
    description: str
    score: float


class SysmonSuspicionScorer:
    def score(self, event: UnifiedSecurityEvent) -> tuple[float, list[SysmonFinding]]:
        data = event.raw_data
        event_id = str(data.get("EventID") or data.get("Id") or event.action)
        text = self._event_text(data)
        findings: list[SysmonFinding] = []

        self._add_if(
            findings,
            "sysmon_event_known",
            event_id in SYSMON_EVENT_NAMES,
            f"Sysmon {event_id}: {SYSMON_EVENT_NAMES.get(event_id, 'Unknown')}",
            0.15,
        )
        self._add_if(
            findings,
            "powershell_encoded",
            "powershell" in text and ("-enc" in text or "encodedcommand" in text),
            "PowerShell encoded command usage.",
            0.9,
        )
        self._add_if(
            findings,
            "shell_spawns_powershell",
            "cmd.exe" in text and "powershell" in text,
            "Command shell spawning PowerShell.",
            0.7,
        )
        self._add_if(
            findings,
            "lolbin_download",
            any(tool in text for tool in ("certutil", "curl", "wget", "bitsadmin"))
            and any(term in text for term in ("http://", "https://", "download", "-urlcache")),
            "Living-off-the-land download behavior.",
            0.78,
        )
        self._add_if(
            findings,
            "lsass_access",
            event_id == "10" and "lsass.exe" in text,
            "Process access to LSASS.",
            0.92,
        )
        self._add_if(
            findings,
            "autorun_registry_write",
            event_id == "13"
            and any(key in text for key in ("\\run\\", "\\runonce\\", "currentversion\\run")),
            "Autorun registry persistence write.",
            0.82,
        )
        self._add_if(
            findings,
            "archive_creation",
            event_id in {"1", "11"}
            and any(
                term in text
                for term in ("archive", ".zip", "compress-archive", "rar.exe", "7z.exe")
            ),
            "Archive creation or staging.",
            0.55,
        )
        self._add_if(
            findings,
            "outbound_public_ip",
            event_id == "3" and self._looks_public_destination(data),
            "Outbound connection to public remote address.",
            0.58,
        )
        self._add_if(
            findings,
            "suspicious_dns",
            event_id == "22"
            and any(
                term in text for term in ("pastebin", "ngrok", "duckdns", "onion", "discordapp")
            ),
            "DNS query to suspicious infrastructure pattern.",
            0.65,
        )

        if not findings:
            return event.anomaly_score or 0.25, []
        return max(finding.score for finding in findings), findings

    def enrich(self, event: UnifiedSecurityEvent) -> UnifiedSecurityEvent:
        score, findings = self.score(event)
        event.anomaly_score = max(event.anomaly_score or 0.0, score)
        event.notes.extend(
            f"sysmon:{finding.rule_id}:{finding.description}" for finding in findings
        )
        return event

    def _event_text(self, data: dict[str, Any]) -> str:
        return " ".join(str(value).lower() for value in data.values() if value is not None)

    def _add_if(
        self,
        findings: list[SysmonFinding],
        rule_id: str,
        condition: bool,
        description: str,
        score: float,
    ) -> None:
        if condition:
            findings.append(SysmonFinding(rule_id=rule_id, description=description, score=score))

    def _looks_public_destination(self, data: dict[str, Any]) -> bool:
        destination = str(data.get("DestinationIp") or "")
        if not destination or destination.startswith(("10.", "127.", "169.254.", "192.168.")):
            return False
        if destination.startswith("172."):
            parts = destination.split(".")
            if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
                return False
        return True
