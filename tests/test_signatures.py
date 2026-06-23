import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rai_scan.cli import main
from rai_scan.config import load_signatures


class SignatureCatalogTests(unittest.TestCase):
    def test_docx_expanded_catalog(self):
        data = load_signatures()
        self.assertEqual(data["version"], "3.0.0")
        self.assertGreaterEqual(len(data["agents"]), 95)
        for agent_id in (
            "claw_code",
            "roo_code",
            "kilo_code",
            "open_interpreter",
            "cline",
            "openclaw",
            "jan",
            "open_webui",
        ):
            self.assertIn(agent_id, data["agents"])
        self.assertNotIn("openai_cli", data["agents"])
        self.assertNotIn("postman_ai", data["agents"])
        self.assertEqual(data["agents"]["cursor_agent"]["config_dirs"], [])
        aliases = data["catalog_only"]["covered_by_other_signature"]
        self.assertEqual(aliases["Roo Code CLI"], "roo_code")
        self.assertEqual(aliases["Kilo Code CLI"], "kilo_code")

    def test_all_signatures_have_homepage(self):
        data = load_signatures()
        missing = []
        for agent_id, sig in data["agents"].items():
            if not sig.get("homepage"):
                missing.append(agent_id)
        if missing:
            self.fail(
                "Signatures missing homepage: {}. "
                "Add a valid URL or use https://github.com/<org>/<repo> placeholder.".format(
                    ", ".join(sorted(missing))
                )
            )

    def test_add_signature_stores_only_custom_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            bundled = load_signatures()
            state.mkdir(parents=True, exist_ok=True)
            (state / "signatures.json").write_text(json.dumps(bundled))
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                result = main(["add-sig", "--name", "Demo-Agent", "--bin", "demo-agent"])
            self.assertEqual(result, 0)
            custom = json.loads((state / "signatures.json").read_text())
            self.assertEqual(list(custom["agents"]), ["demo_agent"])

    def test_add_signature_rejects_path_outside_home(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                result = main(["add-sig", "--name", "Unsafe", "--config", "/etc/ssh"])
            self.assertEqual(result, 1)
            self.assertFalse((state / "signatures.json").exists())

    def test_malformed_signature_lists_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            state = root / "state"
            home.mkdir()
            state.mkdir()
            malformed = {
                "agents": {
                    "bad": {
                        "binaries": [],
                        "config_dirs": [],
                        "cache_dirs": [],
                        "shell_patterns": [123],
                    }
                }
            }
            (state / "signatures.json").write_text(json.dumps(malformed))
            with patch("rai_scan.config.Path.home", return_value=home), patch.dict(
                os.environ, {"RAI_SCAN_HOME": str(state)}
            ):
                data = load_signatures()
            self.assertNotIn("bad", data["agents"])


if __name__ == "__main__":
    unittest.main()
