"""Prompt-injection hardening for the reasoning layer."""

from __future__ import annotations

from copy import deepcopy
import base64
import json
import re
from typing import Any


PROMPTLIKE_PATTERNS = [
    re.compile(r"\b(system|assistant|developer|user)\s*:", re.IGNORECASE),
    re.compile(r"\b(ignore|override|forget)\b.{0,40}\b(instruction|prompt|analysis|policy)\b", re.IGNORECASE),
    re.compile(r"\bset\s+confidence\s+to\b", re.IGNORECASE),
    re.compile(r"\btake\s+no\s+action\b", re.IGNORECASE),
]

BASE64ISH = re.compile(r"^[A-Za-z0-9+/]{32,}={0,2}$")


class PromptInjectionDefense:
    def sanitize_context(self, context: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        sanitized = deepcopy(context)
        flags: list[str] = []
        for event in sanitized.get("events", []):
            self._sanitize_mapping(event, flags)
        return sanitized, flags

    def _sanitize_mapping(self, mapping: dict[str, Any], flags: list[str], path: str = "") -> None:
        for key, value in list(mapping.items()):
            current_path = f"{path}.{key}" if path else str(key)
            if isinstance(value, dict):
                self._sanitize_mapping(value, flags, current_path)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        self._sanitize_mapping(item, flags, f"{current_path}[{index}]")
                    elif isinstance(item, str):
                        value[index] = self._sanitize_string(item, flags, f"{current_path}[{index}]")
            elif isinstance(value, str):
                mapping[key] = self._sanitize_string(value, flags, current_path)

    def _sanitize_string(self, value: str, flags: list[str], path: str) -> str:
        safe = value
        for pattern in PROMPTLIKE_PATTERNS:
            if pattern.search(safe):
                flags.append(f"promptlike_text:{path}")
                safe = pattern.sub("[REDACTED_PROMPTLIKE_TEXT]", safe)
        if BASE64ISH.match(safe):
            try:
                base64.b64decode(safe, validate=True)
                flags.append(f"base64_like:{path}")
                safe = "[REDACTED_BASE64_LIKE_VALUE]"
            except Exception:
                pass
        if any(ord(char) > 127 for char in safe):
            flags.append(f"non_ascii:{path}")
            safe = safe.encode("ascii", "backslashreplace").decode("ascii")
        return safe

    def validate_output(self, output: str | dict[str, Any]) -> tuple[bool, list[str]]:
        data = json.loads(output) if isinstance(output, str) else output
        flags: list[str] = []
        required = {"attack_stage", "matched_techniques", "predicted_next", "confidence_score", "narrative_explanation"}
        missing = required - set(data)
        if missing:
            flags.append(f"missing_fields:{','.join(sorted(missing))}")
        confidence = data.get("confidence_score")
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            flags.append("invalid_confidence")
        text = json.dumps(data).lower()
        if "take no action" in text or "lower alert" in text:
            flags.append("suppression_language_requires_human_review")
        return not flags, flags

    def compare_consistency(self, first: dict[str, Any], second: dict[str, Any]) -> tuple[bool, list[str]]:
        flags: list[str] = []
        if first.get("attack_stage") != second.get("attack_stage"):
            flags.append("stage_divergence")
        first_conf = float(first.get("confidence_score", 0))
        second_conf = float(second.get("confidence_score", 0))
        if abs(first_conf - second_conf) > 0.25:
            flags.append("confidence_divergence")
        return not flags, flags


class CanaryEventMonitor:
    def __init__(self, required_stage: str) -> None:
        self.required_stage = required_stage

    def evaluate(self, reasoning_output: dict[str, Any]) -> bool:
        return reasoning_output.get("attack_stage") == self.required_stage

