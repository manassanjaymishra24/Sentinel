"""Unified event schema and log normalization helpers."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, cast
from uuid import uuid4

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class UnifiedSecurityEvent:
    timestamp: datetime
    event_id: str
    source_system: str
    entity_type: str
    entity_id: str | None
    entity_name: str | None
    action: str
    target_entity: str | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)
    anomaly_score: float | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "source_system": self.source_system,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "action": self.action,
            "target_entity": self.target_entity,
            "raw_data": self.raw_data,
            "anomaly_score": self.anomaly_score,
            "notes": self.notes,
        }


class EventParser(Protocol):
    source_system: str

    def parse(self, raw: str | dict[str, Any]) -> UnifiedSecurityEvent: ...


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        LOGGER.warning("timestamp missing; using current UTC time")
        return datetime.now(timezone.utc)
    text = str(value).replace("Z", "+00:00")
    powershell_json_date = re.fullmatch(r"/Date\((\d+)\)/", text)
    if powershell_json_date:
        milliseconds = int(powershell_json_date.group(1))
        return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        LOGGER.warning("timestamp %r could not be parsed; using current UTC time", value)
        return datetime.now(timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _raw_dict(raw: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    return cast(dict[str, Any], json.loads(raw))


def _event_id(data: dict[str, Any]) -> str:
    return str(
        data.get("event_id")
        or data.get("EventRecordID")
        or data.get("RecordId")
        or data.get("uid")
        or uuid4()
    )


class WindowsEventLogParser:
    source_system = "windows_event_log"

    def parse(self, raw: str | dict[str, Any]) -> UnifiedSecurityEvent:
        data = _raw_dict(raw)
        return UnifiedSecurityEvent(
            timestamp=_parse_timestamp(data.get("TimeCreated") or data.get("timestamp")),
            event_id=_event_id(data),
            source_system=self.source_system,
            entity_type="user",
            entity_id=data.get("SubjectUserSid") or data.get("TargetUserSid"),
            entity_name=data.get("TargetUserName")
            or data.get("SubjectUserName")
            or data.get("ProviderName"),
            action=str(
                data.get("EventID") or data.get("Id") or data.get("event_code") or "windows_event"
            ),
            target_entity=data.get("Computer")
            or data.get("MachineName")
            or data.get("WorkstationName"),
            raw_data=data,
        )


class SysmonParser:
    source_system = "sysmon"

    def parse(self, raw: str | dict[str, Any]) -> UnifiedSecurityEvent:
        data = _raw_dict(raw)
        action = str(
            data.get("EventID") or data.get("Id") or data.get("event_id") or "sysmon_event"
        )
        entity_type = self._entity_type(action)
        entity_id = (
            data.get("ProcessGuid")
            or data.get("ProcessId")
            or data.get("SourceProcessGuid")
            or data.get("SourceProcessId")
        )
        entity_name = data.get("Image") or data.get("SourceImage") or data.get("CommandLine")
        return UnifiedSecurityEvent(
            timestamp=_parse_timestamp(
                data.get("UtcTime") or data.get("TimeCreated") or data.get("timestamp")
            ),
            event_id=_event_id(data),
            source_system=self.source_system,
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name,
            action=action,
            target_entity=(
                data.get("DestinationIp")
                or data.get("QueryName")
                or data.get("TargetObject")
                or data.get("TargetFilename")
                or data.get("TargetImage")
                or data.get("ParentImage")
            ),
            raw_data=data,
        )

    def _entity_type(self, event_id: str) -> str:
        if event_id in {"3", "22"}:
            return "network"
        if event_id in {"11"}:
            return "file"
        if event_id in {"12", "13", "14"}:
            return "registry"
        return "process"


class LinuxAuditdParser:
    source_system = "linux_auditd"

    def parse(self, raw: str | dict[str, Any]) -> UnifiedSecurityEvent:
        data = _raw_dict(raw)
        return UnifiedSecurityEvent(
            timestamp=_parse_timestamp(data.get("timestamp") or data.get("time")),
            event_id=_event_id(data),
            source_system=self.source_system,
            entity_type="process",
            entity_id=data.get("pid"),
            entity_name=data.get("exe") or data.get("comm"),
            action=str(data.get("type") or data.get("syscall") or "audit_event"),
            target_entity=data.get("name") or data.get("addr") or data.get("hostname"),
            raw_data=data,
        )


class ZeekParser:
    source_system = "zeek"

    def parse(self, raw: str | dict[str, Any]) -> UnifiedSecurityEvent:
        data = _raw_dict(raw)
        source = data.get("id.orig_h") or data.get("src_ip")
        destination = data.get("id.resp_h") or data.get("dest_ip")
        return UnifiedSecurityEvent(
            timestamp=_parse_timestamp(data.get("ts") or data.get("timestamp")),
            event_id=_event_id(data),
            source_system=self.source_system,
            entity_type="network",
            entity_id=source,
            entity_name=source,
            action=str(data.get("proto") or data.get("_path") or "network_connection"),
            target_entity=destination,
            raw_data=data,
        )


class CloudTrailParser:
    source_system = "aws_cloudtrail"

    def parse(self, raw: str | dict[str, Any]) -> UnifiedSecurityEvent:
        data = _raw_dict(raw)
        user = data.get("userIdentity", {})
        return UnifiedSecurityEvent(
            timestamp=_parse_timestamp(data.get("eventTime")),
            event_id=_event_id(data),
            source_system=self.source_system,
            entity_type="user",
            entity_id=user.get("principalId") if isinstance(user, dict) else None,
            entity_name=user.get("arn") if isinstance(user, dict) else None,
            action=str(data.get("eventName") or "cloudtrail_event"),
            target_entity=data.get("eventSource") or data.get("recipientAccountId"),
            raw_data=data,
        )


class InMemoryEventBus:
    """Small Kafka-shaped test double for local development."""

    def __init__(self) -> None:
        self._topics: dict[str, list[UnifiedSecurityEvent]] = {}

    def publish(self, topic: str, event: UnifiedSecurityEvent) -> None:
        self._topics.setdefault(topic, []).append(event)

    def consume(self, topic: str) -> list[UnifiedSecurityEvent]:
        events = self._topics.get(topic, [])
        self._topics[topic] = []
        return events
