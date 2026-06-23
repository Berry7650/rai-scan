import unittest
from unittest.mock import patch

from rai_scan.tui.guided import _removal_wizard, recommendations


class GuidedMenuTests(unittest.TestCase):
    def test_only_agent_without_binary_or_package_is_likely_leftover(self):
        manifest = {
            "agents": [
                {
                    "id": "installed",
                    "total_bytes": 10,
                    "artifacts": [{"type": "binary", "path": "/home/user/bin/tool"}],
                    "packages": [],
                },
                {
                    "id": "leftover",
                    "total_bytes": 20,
                    "artifacts": [{"type": "config", "path": "/home/user/.tool"}],
                    "packages": [],
                },
            ]
        }
        results = {agent_id: automatic for agent_id, _reason, automatic in recommendations(manifest)}
        self.assertFalse(results["installed"])
        self.assertTrue(results["leftover"])

    def test_removal_wizard_refreshes_before_selection(self):
        old = {"agents": [], "include_root": False}
        fresh = {"agents": [], "include_root": False}
        with patch("rai_scan.tui.guided.scan_system", return_value=fresh) as scan, patch(
            "rai_scan.tui.guided._choose_agents", return_value=[]
        ) as choose:
            _removal_wizard(old)
        scan.assert_called_once_with(include_root=False)
        choose.assert_called_once_with(fresh)


if __name__ == "__main__":
    unittest.main()
