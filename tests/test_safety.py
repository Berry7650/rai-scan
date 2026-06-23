import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rai_scan.config import load_signatures
from rai_scan.models import Artifact
from rai_scan.removal.engine import _trash_destination, remove_agents
from rai_scan.removal.rollback import append_record, rollback_last
from rai_scan.probes.shell_probe import scan as scan_shell
from rai_scan.scanner import scan_system


class SafetyTests(unittest.TestCase):
    def test_state_directory_and_cache_are_private(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            old_umask = os.umask(0o022)
            try:
                with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                    scan_system(write_cache=True)
            finally:
                os.umask(old_umask)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((state / "last_scan.json").stat().st_mode), 0o600
            )

    def test_symlinked_shell_file_is_not_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            state = root / "state"
            home.mkdir()
            victim = root / "victim"
            victim.write_text("ORIGINAL\n")
            shell = home / ".bashrc"
            shell.symlink_to(victim)
            agent = {
                "id": "demo",
                "display_name": "Demo",
                "total_bytes": 0,
                "artifacts": [],
                "packages": [],
                "shell_lines": [
                    {
                        "file": str(shell),
                        "line_number": 1,
                        "content": "ORIGINAL",
                        "agent_hint": "demo",
                    }
                ],
                "daemons": [],
            }
            with patch("rai_scan.removal.engine.Path.home", return_value=home), patch.dict(
                os.environ, {"RAI_SCAN_HOME": str(state)}
            ):
                record, errors = remove_agents([agent])
            self.assertEqual(record["state"], "partial")
            self.assertTrue(errors)
            self.assertEqual(victim.read_text(), "ORIGINAL\n")

    def test_rollback_journal_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir()
            outside = Path(directory) / "outside"
            outside.write_text("KEEP\n")
            (state / "rollback.log").symlink_to(outside)
            record = {
                "session_id": "session",
                "state": "complete",
                "files_moved_to_trash": [],
                "packages_uninstalled": [],
                "shell_lines_commented": [],
                "daemons_disabled": [],
                "daemons_trashed": [],
            }
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                with self.assertRaises(PermissionError):
                    append_record(record)
            self.assertEqual(outside.read_text(), "KEEP\n")

    def test_tampered_rollback_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            record = {
                "session_id": "session",
                "state": "complete",
                "files_moved_to_trash": [],
                "packages_uninstalled": [],
                "shell_lines_commented": [],
                "daemons_disabled": [],
                "daemons_trashed": [],
            }
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                append_record(record)
                path = state / "rollback.log"
                data = json.loads(path.read_text())
                data["state"] = "partial"
                path.write_text(json.dumps(data) + "\n")
                with self.assertRaisesRegex(RuntimeError, "integrity"):
                    rollback_last()

    def test_trash_names_do_not_collide(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"RAI_SCAN_HOME": directory}):
                first = _trash_destination(
                    "demo", Path("/home/user/a/b__c"), "session"
                )
                second = _trash_destination(
                    "demo", Path("/home/user/a__b/c"), "session"
                )
            self.assertNotEqual(first, second)

    def test_custom_signature_cannot_target_outside_home(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            state = root / "state"
            home.mkdir()
            state.mkdir()
            data = {
                "agents": {
                    "unsafe": {
                        "binaries": [],
                        "config_dirs": ["/etc/ssh"],
                        "cache_dirs": [],
                    }
                }
            }
            (state / "signatures.json").write_text(json.dumps(data))
            with patch("rai_scan.config.Path.home", return_value=home), patch.dict(
                os.environ, {"RAI_SCAN_HOME": str(state)}
            ):
                loaded = load_signatures()
            self.assertNotIn("unsafe", loaded["agents"])

    def test_artifact_identity_change_blocks_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            state = root / "state"
            home.mkdir()
            path = home / ".demo"
            path.write_text("old")
            info = path.lstat()
            artifact = Artifact(
                str(path),
                "config",
                3,
                info.st_mtime,
                "demo",
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_size,
            )
            path.unlink()
            path.write_text("new")
            agent = {
                "id": "demo",
                "display_name": "Demo",
                "total_bytes": 3,
                "artifacts": [artifact.__dict__],
                "packages": [],
                "shell_lines": [],
                "daemons": [],
            }
            with patch("rai_scan.removal.engine.Path.home", return_value=home), patch.dict(
                os.environ, {"RAI_SCAN_HOME": str(state)}
            ):
                record, errors = remove_agents([agent])
            self.assertEqual(record["state"], "partial")
            self.assertTrue(errors)
            self.assertEqual(path.read_text(), "new")

    def test_shell_round_trip_preserves_non_utf8_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            state = root / "state"
            home.mkdir()
            shell = home / ".bashrc"
            original = b"export DEMO=\xff # demo\n"
            shell.write_bytes(original)
            signatures = {
                "agents": {"demo": {"shell_patterns": ["demo"]}}
            }
            with patch("rai_scan.probes.shell_probe.Path.home", return_value=home):
                lines = scan_shell(signatures)
            agent = {
                "id": "demo",
                "display_name": "Demo",
                "total_bytes": 0,
                "artifacts": [],
                "packages": [],
                "shell_lines": [lines[0].__dict__],
                "daemons": [],
            }
            with patch("rai_scan.removal.engine.Path.home", return_value=home), patch.dict(
                os.environ, {"RAI_SCAN_HOME": str(state)}
            ):
                record, errors = remove_agents([agent])
            self.assertFalse(errors)
            self.assertIn(b"# rai-scan disabled", shell.read_bytes())
            with patch("rai_scan.removal.rollback.Path.home", return_value=home), patch.dict(
                os.environ, {"RAI_SCAN_HOME": str(state)}
            ):
                restored = rollback_last()
            self.assertEqual(restored["state"], "rolled_back")
            self.assertEqual(shell.read_bytes(), original)

    def test_unsafe_package_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            agent = {
                "id": "demo",
                "display_name": "Demo",
                "total_bytes": 0,
                "artifacts": [],
                "packages": [
                    {"manager": "npm", "name": "--prefix", "scope": "user"}
                ],
                "shell_lines": [],
                "daemons": [],
            }
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}), patch(
                "rai_scan.removal.engine.subprocess.run"
            ) as run:
                record, errors = remove_agents([agent])
            self.assertEqual(record["state"], "partial")
            self.assertIn("unsafe package", errors[0])
            run.assert_not_called()
