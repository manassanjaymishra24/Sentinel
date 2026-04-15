import unittest

from sentinel.events import CloudTrailParser, SysmonParser, WindowsEventLogParser, ZeekParser
from sentinel.sysmon import SysmonSuspicionScorer
from sentinel.windows_events import WindowsEventLogReader, quote_powershell_string


class EventParserTests(unittest.TestCase):
    def test_sysmon_parser_normalizes_process_event(self):
        event = SysmonParser().parse(
            {
                "UtcTime": "2026-04-15T12:00:00Z",
                "EventID": "1",
                "ProcessGuid": "{abc}",
                "Image": "powershell.exe",
                "ParentImage": "explorer.exe",
            }
        )

        self.assertEqual(event.source_system, "sysmon")
        self.assertEqual(event.entity_type, "process")
        self.assertEqual(event.entity_id, "{abc}")
        self.assertEqual(event.target_entity, "explorer.exe")

    def test_sysmon_parser_normalizes_network_event(self):
        event = SysmonParser().parse(
            {
                "UtcTime": "2026-04-15T12:00:00Z",
                "EventID": "3",
                "ProcessGuid": "{abc}",
                "ProcessId": "1234",
                "Image": "curl.exe",
                "DestinationIp": "203.0.113.10",
            }
        )

        self.assertEqual(event.entity_type, "network")
        self.assertEqual(event.entity_id, "{abc}")
        self.assertEqual(event.target_entity, "203.0.113.10")

    def test_sysmon_scorer_flags_encoded_powershell(self):
        event = SysmonParser().parse(
            {
                "UtcTime": "2026-04-15T12:00:00Z",
                "EventID": "1",
                "ProcessId": "1234",
                "Image": "powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
            }
        )

        enriched = SysmonSuspicionScorer().enrich(event)

        self.assertGreaterEqual(enriched.anomaly_score, 0.9)
        self.assertTrue(any("powershell_encoded" in note for note in enriched.notes))

    def test_windows_parser_normalizes_auth_event(self):
        event = WindowsEventLogParser().parse(
            {
                "TimeCreated": "2026-04-15T12:00:00Z",
                "EventID": 4624,
                "TargetUserSid": "S-1-5-21",
                "TargetUserName": "alice",
                "Computer": "workstation-1",
            }
        )

        self.assertEqual(event.entity_type, "user")
        self.assertEqual(event.entity_name, "alice")
        self.assertEqual(event.action, "4624")

    def test_windows_parser_handles_get_winevent_shape(self):
        event = WindowsEventLogParser().parse(
            {
                "TimeCreated": "/Date(1776254400000)/",
                "Id": 4104,
                "RecordId": 123,
                "ProviderName": "Microsoft-Windows-PowerShell",
                "MachineName": "workstation-1",
                "Message": "PowerShell script block logging",
            }
        )

        self.assertEqual(event.event_id, "123")
        self.assertEqual(event.action, "4104")
        self.assertEqual(event.entity_name, "Microsoft-Windows-PowerShell")
        self.assertEqual(event.target_entity, "workstation-1")
        self.assertEqual(event.timestamp.year, 2026)

    def test_zeek_parser_normalizes_network_event(self):
        event = ZeekParser().parse(
            {
                "ts": "2026-04-15T12:00:00Z",
                "uid": "C1",
                "id.orig_h": "10.0.0.5",
                "id.resp_h": "198.51.100.10",
                "proto": "tcp",
            }
        )

        self.assertEqual(event.entity_type, "network")
        self.assertEqual(event.entity_id, "10.0.0.5")
        self.assertEqual(event.target_entity, "198.51.100.10")

    def test_cloudtrail_parser_normalizes_identity_event(self):
        event = CloudTrailParser().parse(
            {
                "eventTime": "2026-04-15T12:00:00Z",
                "eventName": "CreateAccessKey",
                "eventSource": "iam.amazonaws.com",
                "userIdentity": {"principalId": "AID123", "arn": "arn:aws:iam::123:user/alice"},
            }
        )

        self.assertEqual(event.source_system, "aws_cloudtrail")
        self.assertEqual(event.entity_id, "AID123")
        self.assertEqual(event.action, "CreateAccessKey")

    def test_windows_reader_parses_json_array_and_records_errors(self):
        reader = WindowsEventLogReader(log_names=["System"])
        raw_events = reader._parse_json_output(
            '[{"LogName":"System","Id":7045,"RecordId":1,"TimeCreated":"2026-04-15T12:00:00Z"},'
            '{"LogName":"Security","Error":"Access denied"}]'
        )

        self.assertEqual(len(raw_events), 2)
        self.assertEqual(raw_events[0]["Id"], 7045)

    def test_windows_reader_command_escapes_log_names(self):
        self.assertEqual(quote_powershell_string("Bob's Log"), "'Bob''s Log'")
        command = WindowsEventLogReader(log_names=["System"], since_minutes=1, max_events=2).build_command()

        self.assertIn("powershell", command[0])
        self.assertIn("System", command[-1])
        self.assertIn("MaxEvents 2", command[-1])

    def test_windows_reader_expands_sysmon_message(self):
        reader = WindowsEventLogReader(log_names=["Microsoft-Windows-Sysmon/Operational"])
        event = reader._parse_event(
            {
                "LogName": "Microsoft-Windows-Sysmon/Operational",
                "Id": 1,
                "RecordId": 99,
                "TimeCreated": "2026-04-15T12:00:00Z",
                "Message": "ProcessId: 1234\nImage: powershell.exe\nCommandLine: powershell.exe -EncodedCommand SQBFAFgA",
            }
        )

        self.assertEqual(event.source_system, "sysmon")
        self.assertEqual(event.entity_id, "1234")
        self.assertGreaterEqual(event.anomaly_score, 0.9)


if __name__ == "__main__":
    unittest.main()
