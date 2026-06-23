import unittest
from unittest.mock import patch

from rai_scan.report import as_html, as_list, as_markdown


class ReportTests(unittest.TestCase):
    def test_reports_escape_content(self):
        manifest = {
            "scan_time": "2026-01-01",
            "total_reclaimable_bytes": 4,
            "agents": [
                {
                    "display_name": "<demo>",
                    "confidence": "high",
                    "total_bytes": 4,
                    "artifacts": [{"path": "/x/<y>", "type": "config", "size_bytes": 4}],
                    "packages": [],
                    "shell_lines": [],
                    "daemons": [],
                }
            ],
        }
        self.assertIn("&lt;demo&gt;", as_html(manifest))
        self.assertIn("| 1 | <demo>", as_markdown(manifest))

    def test_list_uses_color_only_when_terminal_color_is_enabled(self):
        manifest = {
            "scan_time": "2026-01-01",
            "total_reclaimable_bytes": 4,
            "agents": [
                {
                    "display_name": "Demo",
                    "confidence": "high",
                    "total_bytes": 4,
                    "artifacts": [],
                    "packages": [],
                    "shell_lines": [],
                    "daemons": [],
                }
            ],
            "ai_related": [],
            "orphans": [],
        }
        plain = as_list(manifest)
        self.assertNotIn("\033[", plain)
        with patch("rai_scan.color.enabled", return_value=True):
            colored = as_list(manifest)
        self.assertIn("\033[", colored)


if __name__ == "__main__":
    unittest.main()
